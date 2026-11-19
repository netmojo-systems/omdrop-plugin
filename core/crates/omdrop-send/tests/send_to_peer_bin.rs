//! `send-to-peer` as a black box, with every outside program stubbed: the
//! binary is copied into a temporary directory beside a stub `omdrop-adv`
//! and `airdrop-send`, and `pkexec`, `ip` and `loginctl` are stubs first on
//! PATH. Nothing transmits and nothing runs as root.
//!
//! The machine running these tests may have a live `awdl0` (this one does),
//! and a send's knocks go out of `awdl0` by design. So every run happens in
//! private network and mount namespaces (`unshare -rnm`) holding only a
//! dummy `awdl0`, with sysfs remounted so `/sys/class/net` shows that
//! namespace; where this is unavailable the tests skip rather than touch the
//! radio.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

struct Bed {
    dir: tempfile::TempDir,
}

impl Bed {
    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn command(&self, args: &[&str]) -> Command {
        // In the new namespace: a dummy awdl0, then the program in place of
        // the shell (same pid, so signals reach it).
        let mut cmd = Command::new("unshare");
        cmd.args([
            "-rnm",
            "sh",
            "-c",
            "/usr/bin/ip link add awdl0 type dummy && /usr/bin/ip link set awdl0 up && mount -t sysfs sysfs /sys && exec \"$@\"",
            "sh",
        ])
        .arg(self.path("lib/send-to-peer"));
        cmd.args(args)
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.path("bin").display()),
            )
            .env("OMDROP_DISCOVERABLE", self.path("helper"))
            .env("HOME", self.path("home"))
            .env("XDG_CONFIG_HOME", self.path("home/.config"))
            .env("XDG_RUNTIME_DIR", self.path("runtime"))
            .env("STUB_LOG", self.path("stub.log"))
            .env_remove("OMDROP_IMPLEMENTATION")
            .env_remove("OMDROP_NAME_LOG")
            .stdin(Stdio::null());
        cmd
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.path("stub.log")).unwrap_or_default()
    }
}

/// Write an executable without this test process ever holding it open for
/// writing: a fork made by a parallel test while we held it would inherit the
/// descriptor until it execs, and running the file then fails with ETXTBSY.
/// A child that writes it and exits holds the only write descriptor.
fn script(path: &Path, body: &str) {
    use std::io::Write;
    let mut child = Command::new("sh")
        .args(["-c", "cat > \"$1\" && chmod 755 \"$1\"", "sh"])
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin
        .write_all(format!("#!/bin/sh\n{body}").as_bytes())
        .unwrap();
    drop(stdin);
    assert!(
        child.wait().unwrap().success(),
        "writing {}",
        path.display()
    );
}

/// Whether a private network namespace can be made here.
fn sandbox() -> bool {
    let ok = Command::new("unshare")
        .args([
            "-rnm",
            "sh",
            "-c",
            "/usr/bin/ip link add awdl0 type dummy && mount -t sysfs sysfs /sys",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        eprintln!(
            "skipped: no unprivileged network namespace, and these runs must not reach the real awdl0"
        );
    }
    ok
}

fn bed(peers: &str) -> Option<Bed> {
    if !sandbox() {
        return None;
    }
    let dir = tempfile::tempdir().unwrap();
    let bed = Bed { dir };
    for d in ["lib", "bin", "home", "runtime"] {
        std::fs::create_dir_all(bed.path(d)).unwrap();
    }
    // cp, not fs::copy, for the same reason as script().
    assert!(
        Command::new("cp")
            .arg(env!("CARGO_BIN_EXE_send-to-peer"))
            .arg(bed.path("lib/send-to-peer"))
            .status()
            .unwrap()
            .success()
    );
    // pkexec runs its argument as is; the helper prints the table.
    script(
        &bed.path("bin/pkexec"),
        "echo \"pkexec $*\" >> \"$STUB_LOG\"\nexec \"$@\"\n",
    );
    script(
        &bed.path("helper"),
        &format!("[ \"$1\" = peers ] || exit 9\ncat <<'EOF'\n{peers}EOF\n"),
    );
    script(&bed.path("bin/ip"), "exit 0\n");
    script(&bed.path("bin/loginctl"), "echo Seat=seat0\n");
    // The advert: registers, then runs until told to stop, and says so.
    script(
        &bed.path("lib/omdrop-adv"),
        "echo \"adv $*\" >> \"$STUB_LOG\"\ntrap 'echo adv-stopped >> \"$STUB_LOG\"; exit 0' TERM\necho '1.000 00:00:00Z contact hashes: none'\necho '1.000 00:00:00Z START advertising'\nwhile :; do sleep 0.1; done\n",
    );
    script(
        &bed.path("lib/airdrop-send"),
        "echo \"send $*\" >> \"$STUB_LOG\"\nexit 0\n",
    );
    Some(bed)
}

const TWO: &str = "e2:9d:03:6c:58:23  rssi=-47\nfe:63:e6:68:9f:12  rssi=-14\n";

#[test]
fn listing_and_print() {
    let Some(bed) = bed(TWO) else { return };
    let out = bed.command(&["--list"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "fe:63:e6:68:9f:12   -14 dBm  [fe80::fc63:e6ff:fe68:9f12%awdl0]:8770\n\
         e2:9d:03:6c:58:23   -47 dBm  [fe80::e09d:3ff:fe6c:5823%awdl0]:8770\n"
    );
    assert!(
        bed.log()
            .contains(&format!("pkexec {} peers", bed.path("helper").display()))
    );

    let out = bed
        .command(&["--print", "--mac", "e2:9d", "--url", "https://example.com/"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    // The sender's name defaults to the short hostname (driver 0.9.3, 21334f6).
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap();
    let host = host.trim().split('.').next().unwrap().to_owned();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!(
            "{} --direct [fe80::e09d:3ff:fe6c:5823%awdl0]:8770 --op-timeout 60.0 --name {host} --url https://example.com/ --\n",
            bed.path("lib/airdrop-send").display()
        )
    );

    let help = bed.command(&["--help"]).output().unwrap();
    let help = String::from_utf8_lossy(&help.stdout);
    for probe in ["[file ...]", "--url", "--names", "--stream"] {
        assert!(help.contains(probe), "{probe}");
    }
}

#[test]
fn a_peer_without_a_signal_reading_is_listed() {
    // omdrop-owl's helper prints `rssi=?` for a peer it has no reading for.
    let Some(bed) = bed("b2:c4:98:5e:e6:be rssi=?\n22:8b:38:31:89:4e rssi=-34\n") else {
        return;
    };
    let out = bed.command(&["--list"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "22:8b:38:31:89:4e   -34 dBm  [fe80::208b:38ff:fe31:894e%awdl0]:8770\n\
         b2:c4:98:5e:e6:be     ? dBm  [fe80::b0c4:98ff:fe5e:e6be%awdl0]:8770\n"
    );
}

#[test]
fn omdrop_radio_is_used_only_with_backend_hooks() {
    if Path::new("/usr/lib/omdrop/radio").is_dir() {
        eprintln!("skipped: radio hooks are installed here");
        return;
    }
    let Some(bed) = bed(TWO) else { return };
    // A sibling omdrop-radio exists, but no backend hooks do: the legacy
    // helper is the one pkexec is asked to run. pkexec here runs nothing.
    script(&bed.path("lib/omdrop-radio"), "exit 0\n");
    script(
        &bed.path("bin/pkexec"),
        "echo \"pkexec $*\" >> \"$STUB_LOG\"\nexit 126\n",
    );
    let out = bed
        .command(&["--list"])
        .env_remove("OMDROP_DISCOVERABLE")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(4));
    let log = bed.log();
    assert!(
        log.contains("pkexec /usr/lib/omdrop/omdrop-discoverable peers"),
        "{log}"
    );
    assert!(!log.contains("omdrop-radio"), "{log}");
}

#[test]
fn empty_room_and_helper_failure() {
    let Some(bed) = bed("") else { return };
    let out = bed.command(&["--list"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("no devices found:"));

    script(
        &bed.path("helper"),
        "echo 'Error executing command as another user: Not authorized' >&2\nexit 127\n",
    );
    let out = bed.command(&["--list"]).output().unwrap();
    assert_eq!(out.status.code(), Some(4));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        format!(
            "could not read the peer table ({} exited 127): Error executing command as another user: Not authorized\n",
            bed.path("helper").display()
        )
    );
}

#[test]
fn a_send_runs_the_sibling_sender() {
    let Some(bed) = bed("e2:9d:03:6c:58:23  rssi=-47\n") else {
        return;
    };
    let out = bed
        .command(&["--name", "Study Mac", "--", "-photo.jpg"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "sending -photo.jpg to e2:9d:03:6c:58:23 at [fe80::e09d:3ff:fe6c:5823%awdl0]:8770\n"
    );
    assert!(bed.log().contains("send --direct [fe80::e09d:3ff:fe6c:5823%awdl0]:8770 --op-timeout 60.0 --name Study Mac -- -photo.jpg"));
}

#[test]
fn a_wait_raises_the_wake_and_always_takes_it_down() {
    let Some(bed) = bed("e2:9d:03:6c:58:23  rssi=-47\n") else {
        return;
    };
    // Only a dummy awdl0 here, so the peer never opens: the wait runs out.
    let out = bed.command(&["--wait", "2", "f"]).output().unwrap();
    assert_eq!(out.status.code(), Some(3));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("e2:9d:03:6c:58:23 never opened 8770; on an iPhone"),
        "{err}"
    );
    let log = bed.log();
    // The wake covers the wait and the transfer that follows: --wait plus SEND_WAKE_SECONDS.
    assert!(
        log.contains("adv ble --arm A --seconds 302 --interval-ms 100"),
        "{log}"
    );
    assert!(log.contains("adv-stopped"), "{log}");
    assert!(!log.contains("send "), "{log}");
}

#[test]
fn sigterm_during_a_wait_stops_the_advert() {
    let Some(bed) = bed("e2:9d:03:6c:58:23  rssi=-47\n") else {
        return;
    };
    let mut child = bed
        .command(&["--wait", "60", "f"])
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !bed.log().contains("adv ble") {
        assert!(Instant::now() < deadline, "advert never started");
        std::thread::sleep(Duration::from_millis(50));
    }
    std::thread::sleep(Duration::from_millis(300));
    // SAFETY: signalling our own child.
    unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(143));
    assert!(bed.log().contains("adv-stopped"), "{}", bed.log());
}

#[test]
fn a_wake_that_fails_to_register_says_why() {
    let Some(bed) = bed("e2:9d:03:6c:58:23  rssi=-47\n") else {
        return;
    };
    script(
        &bed.path("lib/omdrop-adv"),
        "echo 'omdrop-adv ble: no Bluetooth adapter' >&2\nexit 1\n",
    );
    let out = bed.command(&["--wait", "1", "f"]).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("wake exited: omdrop-adv ble: no Bluetooth adapter; sending without a wake"),
        "{err}"
    );
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn an_unknown_implementation_is_refused_before_anything_runs() {
    let Some(bed) = bed(TWO) else { return };
    let out = bed
        .command(&["--list"])
        .env("OMDROP_IMPLEMENTATION", "pyhton")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "send-to-peer: OMDROP_IMPLEMENTATION must be python or rust, not \"pyhton\"\n"
    );
    assert_eq!(bed.log(), "", "nothing may run");
}
