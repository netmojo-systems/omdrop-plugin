//! The plugin tests that sliced functions out of the bash and ran them in a
//! harness (test_window_arming, test_start_cleanup, test_off_during_send,
//! test_once_shutdown) cannot run against a binary. These are the same
//! checks against `omdrop` itself, with systemd, pkexec, the radio helper
//! and the identity commands stubbed on PATH. Nothing here touches the real
//! session: HOME, XDG_* and the runtime directory are temporary, and every
//! program that could reach the desktop is a stub that only logs.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Fixture {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    capture: PathBuf,
    helper: PathBuf,
    omdrop: PathBuf,
}

const TEMPLATE: &str = "[Service]\nWorkingDirectory=@PLUGIN_DIR@\nExecStart=/usr/bin/python3 @PLUGIN_DIR@/bin/airdrop-serve.py --iface awdl0 --port 8771\n";

/// Stands in for identity.py under OMDROP_IMPLEMENTATION=python, as the bash harness's
/// `id_py` did: `window` answers with $IDENTITY.
const FAKE_IDENTITY: &str = r#"import os, sys
cmd = sys.argv[1]
if cmd == "begin":
    print("seq=0")
elif cmd == "window":
    print(os.environ.get("IDENTITY", "source=self-signed"))
elif cmd.startswith("stop-"):
    with open(os.environ["CAPTURE"], "a") as f:
        f.write(f"identity {cmd}\n")
elif cmd == "ensure-self-signed":
    sys.exit(1)
"#;

/// Write an executable without this test process ever holding it open for
/// writing. Tests run in parallel and fork; a fork made while we held the
/// file open inherits the descriptor until it execs, and running the file in
/// that moment fails with ETXTBSY ("Text file busy"): `omdrop` then took its
/// fallback at once and a timing test saw 0 s. A child that writes it and
/// exits holds the only write descriptor, and it never forks.
fn write_exec(path: &Path, body: &str) {
    use std::io::Write;
    let mut child = Command::new("sh")
        .args(["-c", "cat > \"$1\" && chmod 755 \"$1\"", "sh"])
        .arg(path)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(body.as_bytes())
        .unwrap();
    assert!(
        child.wait().unwrap().success(),
        "writing {}",
        path.display()
    );
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let bin = root.join("bin");
        let plugin = root.join("plugins/netmojo.omdrop");
        for d in [
            bin.clone(),
            plugin.join("bin"),
            plugin.join("share"),
            plugin.join("skills/omdrop"),
            root.join("home"),
            root.join("run"),
        ] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(plugin.join("manifest.json"), r#"{"version": "9.9.9"}"#).unwrap();
        std::fs::write(plugin.join("share/airdrop-receiver.service"), TEMPLATE).unwrap();
        std::fs::write(plugin.join("bin/airdrop-serve.py"), "").unwrap();
        std::fs::write(plugin.join("bin/identity.py"), FAKE_IDENTITY).unwrap();
        std::fs::write(plugin.join("skills/omdrop/SKILL.md"), "skill\n").unwrap();
        let omdrop = plugin.join("bin/omdrop");
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_omdrop"), &omdrop).unwrap();

        let log = r#"printf '%s\n' "$(basename "$0") $*" >> "$CAPTURE""#;
        write_exec(
            &bin.join("systemctl"),
            &format!(
                "#!/bin/sh\n{log}\ncase \"$*\" in\n  *\" is-active \"*) echo \"${{ACTIVE:-inactive}}\"; [ \"$ACTIVE\" = active ] ;;\n  *\" start \"*) exit \"${{START_RC:-0}}\" ;;\n  *) exit 0 ;;\nesac\n"
            ),
        );
        write_exec(
            &bin.join("systemd-run"),
            &format!(
                "#!/bin/sh\n{log}\ncase \"$*\" in *omdrop-identity-expiry*) exit \"${{ARM_RC:-0}}\" ;; esac\nexit 0\n"
            ),
        );
        write_exec(
            &bin.join("pkexec"),
            &format!(
                "#!/bin/sh\n{log}\nprintf 'pkexec-ulimit %s\\n' \"$(ulimit -Hc)\" >> \"$CAPTURE\"\n[ \"$1\" = --disable-internal-agent ] && exit 1\n[ \"$2\" = start ] || exit 0\n[ -n \"$RADIO_SLEEP\" ] && sleep \"$RADIO_SLEEP\"\n[ \"${{RADIO_RC:-0}}\" = 0 ] && exit 0\necho '12:00:08Z supervisor did not start' >&2\nexit \"$RADIO_RC\"\n"
            ),
        );
        write_exec(
            &bin.join("ip"),
            "#!/bin/sh\n[ -n \"$LINK_LOCAL\" ] && echo '    inet6 fe80::1/64 scope link'\nexit 0\n",
        );
        write_exec(
            &bin.join("journalctl"),
            "#!/bin/sh\nprintf '%s\\n' \"$JOURNAL\"\n",
        );
        for quiet in [
            "uwsm-app",
            "wl-copy",
            "omarchy-notification-send",
            "update-desktop-database",
            "update-mime-database",
            "xdg-mime",
        ] {
            write_exec(&bin.join(quiet), &format!("#!/bin/sh\n{log}\n"));
        }
        let helper = root.join("omdrop-discoverable");
        write_exec(
            &helper,
            "#!/bin/sh\nif [ -n \"$VISIBLE\" ]; then echo '{\"visible\":true}'; else echo '{\"visible\":false}'; fi\n",
        );
        // send-to-peer: its help, one peer, and a send that says it is asking.
        // HOLD_STDERR leaves a process of another session holding its stderr.
        write_exec(
            &root.join("sender"),
            "#!/bin/sh\ncase \"$1\" in\n  --help) echo '  [file ...] --url --names --stream'; exit 0 ;;\n  --list) echo 'e2:9d:03:6c:58:23   -47 dBm  [fe80::1%awdl0]:8770  Studio Mac'; exit 0 ;;\nesac\nprintf 'sender-helper %s\\n' \"$OMDROP_DISCOVERABLE\" >> \"$CAPTURE\"\necho '+0.41s FOUND x at y; asking'\n[ -n \"$HOLD_STDERR\" ] && (setsid sleep 8 >/dev/null &)\nexit 0\n",
        );
        let capture = root.join("events");
        std::fs::write(&capture, "").unwrap();
        Self {
            _tmp: tmp,
            root,
            capture,
            helper,
            omdrop,
        }
    }

    fn command(&self, args: &[&str]) -> Command {
        self.command_as(&self.omdrop, args)
    }

    fn command_as(&self, program: &Path, args: &[&str]) -> Command {
        let mut cmd = Command::new(program);
        cmd.args(args)
            .env_clear()
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    self.root.join("bin").display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .env("HOME", self.root.join("home"))
            .env("XDG_CONFIG_HOME", self.root.join("home/.config"))
            .env("XDG_DATA_HOME", self.root.join("home/.local/share"))
            .env("XDG_RUNTIME_DIR", self.root.join("run"))
            .env("OMDROP_DISCOVERABLE", &self.helper)
            .env("OMDROP_SENDER", self.root.join("no-sender"))
            .env("OMDROP_IMPLEMENTATION", "python")
            .env("CAPTURE", &self.capture);
        cmd
    }

    fn run(&self, args: &[&str], env: &[(&str, &str)]) -> (Output, String) {
        let mut cmd = self.command(args);
        for (k, v) in env {
            cmd.env(k, v);
        }
        let out = cmd.output().unwrap();
        let events = std::fs::read_to_string(&self.capture).unwrap();
        (out, events)
    }
}

fn first(events: &str, needle: &str) -> usize {
    events
        .find(needle)
        .unwrap_or_else(|| panic!("{needle:?} not in:\n{events}"))
}

fn last(events: &str, needle: &str) -> usize {
    events
        .rfind(needle)
        .unwrap_or_else(|| panic!("{needle:?} not in:\n{events}"))
}

#[test]
fn an_unknown_implementation_is_refused_before_anything_runs() {
    let f = Fixture::new();
    let (out, ev) = f.run(&["on", "10m"], &[("OMDROP_IMPLEMENTATION", "pyhton")]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "omdrop: OMDROP_IMPLEMENTATION must be python or rust, not \"pyhton\"\n"
    );
    assert!(!ev.contains("pkexec"), "{ev}");
}

#[test]
fn the_window_is_named_before_the_radio_comes_up() {
    let f = Fixture::new();
    let (out, ev) = f.run(&["on", "10m"], &[]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        first(&ev, "watch --window 10m") < first(&ev, "pkexec"),
        "{ev}"
    );
}

#[test]
fn the_clock_starts_only_once_receiving_works() {
    let f = Fixture::new();
    let (_, ev) = f.run(&["on", "10m"], &[]);
    let armed = first(&ev, "on-active=10m");
    assert!(armed > first(&ev, "pkexec"), "{ev}");
    assert!(
        armed > first(&ev, "--user start airdrop-receiver.service"),
        "{ev}"
    );
}

#[test]
fn the_radio_is_asked_for_the_window_again_from_that_moment() {
    let f = Fixture::new();
    let (_, ev) = f.run(&["on", "10m"], &[]);
    assert_eq!(
        ev.lines().filter(|l| l.contains("start 600")).count(),
        2,
        "{ev}"
    );
    assert!(last(&ev, "start 600") > first(&ev, "on-active=10m"), "{ev}");
}

#[test]
fn a_one_file_window_declares_itself_before_the_radio() {
    let f = Fixture::new();
    let (_, ev) = f.run(&["on", "once"], &[]);
    assert!(first(&ev, "watch --once") < first(&ev, "pkexec"), "{ev}");
    assert!(!ev.contains("on-active"), "{ev}");
}

#[test]
fn an_unbounded_window_arms_no_timer_and_names_no_span() {
    let f = Fixture::new();
    let (_, ev) = f.run(&["on", "forever"], &[]);
    assert!(!ev.contains("on-active"), "{ev}");
    assert!(ev.contains(" watch"), "{ev}");
    assert!(!ev.contains("--once") && !ev.contains("--window"), "{ev}");
}

#[test]
fn a_radio_that_will_not_start_leaves_no_window_behind() {
    let f = Fixture::new();
    let (out, ev) = f.run(&["on", "10m"], &[("RADIO_RC", "1")]);
    assert_eq!(out.status.code(), Some(1), "{ev}");
    assert_eq!(
        String::from_utf8_lossy(&out.stderr).trim(),
        "supervisor did not start"
    );
    assert_eq!(ev.matches("stop omdrop-window.timer").count(), 2, "{ev}");
    assert!(ev.contains("identity stop-end"), "{ev}");
    assert!(!ev.contains("on-active"), "{ev}");
}

#[test]
fn a_1password_window_arms_its_hard_expiry_before_anything_starts() {
    let f = Fixture::new();
    let (_, ev) = f.run(
        &["on", "10m"],
        &[("IDENTITY", "source=1password\nexpiry_in=3600")],
    );
    assert!(
        ev.contains("--on-active=3600s --unit=omdrop-identity-expiry"),
        "{ev}"
    );
    assert!(
        first(&ev, "omdrop-identity-expiry") < first(&ev, "pkexec"),
        "{ev}"
    );
}

#[test]
fn a_window_whose_hard_expiry_cannot_be_armed_never_starts() {
    let f = Fixture::new();
    let (out, ev) = f.run(
        &["on", "10m"],
        &[
            ("IDENTITY", "source=1password\nexpiry_in=3600"),
            ("ARM_RC", "1"),
        ],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(ev.contains("identity stop-end"), "{ev}");
    assert!(!ev.contains("pkexec"), "{ev}");
    assert!(!ev.contains("--user start"), "{ev}");
}

#[test]
fn a_window_turned_off_while_starting_exits_quietly() {
    let f = Fixture::new();
    // identity.py's `window` exits 3 when an `off` ran during the fetch.
    let plugin = f.root.join("plugins/netmojo.omdrop/bin/identity.py");
    let body = FAKE_IDENTITY.replace(
        "print(os.environ.get(\"IDENTITY\", \"source=self-signed\"))",
        "sys.exit(3)",
    );
    std::fs::write(plugin, body).unwrap();
    let (out, ev) = f.run(&["on"], &[]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "Omdrop was turned off while it was starting.\n"
    );
    assert!(!ev.contains("pkexec"), "{ev}");
}

#[test]
fn receiver_first_failure_stops_a_partially_started_radio() {
    let f = Fixture::new();
    let (out, ev) = f.run(&["on", "10m"], &[("LINK_LOCAL", "1"), ("RADIO_RC", "1")]);
    assert_eq!(out.status.code(), Some(1));
    let stop = format!("pkexec {} stop", f.helper.display());
    assert!(
        first(&ev, "--user start airdrop-receiver.service") < first(&ev, &stop),
        "{ev}"
    );
    assert!(ev.contains("--user stop airdrop-receiver.service"), "{ev}");
}

#[test]
fn off_refuses_while_a_send_is_running_and_force_overrides() {
    let f = Fixture::new();
    let sends = f.root.join("run/omdrop/sends");
    std::fs::create_dir_all(&sends).unwrap();
    let mut live = Command::new("sleep").arg("30").spawn().unwrap();
    std::fs::write(sends.join(live.id().to_string()), "hume\n").unwrap();

    let (out, ev) = f.run(&["off"], &[]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_ne!(out.status.code(), Some(0));
    assert!(
        err.contains("Still sending to hume") && err.contains("omdrop off --force"),
        "{err}"
    );
    assert!(!ev.contains(" stop "), "{ev}");

    let (out, ev) = f.run(&["off", "--force"], &[]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        ev.contains("systemctl --user stop airdrop-receiver.service"),
        "{ev}"
    );
    assert!(
        first(&ev, "identity stop-begin") < first(&ev, "--user stop airdrop-receiver.service"),
        "{ev}"
    );
    assert!(
        first(&ev, "--user stop airdrop-receiver.service") < first(&ev, "identity stop-end"),
        "{ev}"
    );
    live.kill().unwrap();
    live.wait().unwrap();
}

fn arrival(f: &Fixture, name: &str) -> PathBuf {
    let downloads = f.root.join("home/Downloads");
    std::fs::create_dir_all(&downloads).unwrap();
    let file = downloads.join(name);
    std::fs::write(&file, "x").unwrap();
    file
}

const TS: &str = "2026-10-10 16:14:20,098 INFO root: ";

#[test]
fn a_one_file_window_closes_in_a_unit_of_its_own() {
    let f = Fixture::new();
    arrival(&f, "arrived.jpg");
    let journal = format!("{TS}upload ABC: stored arrived.jpg");
    let (out, ev) = f.run(&["watch", "--once"], &[("JOURNAL", &journal)]);
    assert!(out.status.success());
    assert!(
        ev.lines()
            .any(|l| l.starts_with("systemd-run --user --quiet --collect ")
                && l.ends_with(" off --force")),
        "{ev}"
    );

    let f = Fixture::new();
    let file = arrival(&f, "arrived.jpg");
    let journal = format!("{TS}upload ABC: stored arrived.jpg");
    let (out, ev) = f.run(&["watch", "--window", "10m"], &[("JOURNAL", &journal)]);
    assert!(out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stdout)
            .contains(&format!("omdrop watch: announcing {}", file.display()))
    );
    assert!(!ev.lines().any(|l| l.ends_with(" off --force")), "{ev}");
}

#[test]
fn a_forged_record_naming_a_file_outside_the_download_folder_is_ignored() {
    let f = Fixture::new();
    arrival(&f, "unrelated.jpg");
    let secret = f.root.join("secret.png");
    std::fs::write(&secret, "x").unwrap();
    // Neither the receiver's own format, nor a name inside the folder: no
    // announcement, and a one-file window stays open.
    let journal = format!(
        "upload X: stored {s}\n{TS}upload X: stored {s}\n{TS}GET from Mac upload X: stored unrelated.jpg",
        s = secret.display()
    );
    let (out, ev) = f.run(&["watch", "--once"], &[("JOURNAL", &journal)]);
    assert!(out.status.success());
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("announcing"),
        "{ev}"
    );
    assert!(!ev.lines().any(|l| l.ends_with(" off --force")), "{ev}");
    assert!(!ev.contains("secret.png"), "{ev}");
}

#[test]
fn version_names_the_plugin_and_this_program() {
    let f = Fixture::new();
    let (out, _) = f.run(&["version"], &[]);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("omdrop 9.9.9\nomdrop-core {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert!(out.stderr.is_empty());
}

/// The plugin's bin/omdrop asks core its version before handing a command to
/// it, running it directly, where it finds no plugin. It reads the
/// `omdrop-core <version>` line on stdout, so that line must not depend on
/// finding one, and must carry the workspace version the plugin's CORE_MIN is
/// compared against.
#[test]
fn version_reports_this_program_without_a_plugin() {
    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_omdrop"))
        .arg("version")
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", tmp.path())
        .env("XDG_CONFIG_HOME", tmp.path().join("config"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        format!("omdrop-core {}\n", env!("CARGO_PKG_VERSION"))
    );
}

fn spawn_with(f: &Fixture, args: &[&str], env: &[(&str, &str)]) -> std::process::Child {
    let mut cmd = f.command(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap()
}

fn signal(child: &std::process::Child, sig: i32) {
    let pid = i32::try_from(child.id()).unwrap();
    // SAFETY (test): signalling our own child.
    assert_eq!(unsafe { libc_kill(pid, sig) }, 0);
}

unsafe extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, sig: i32) -> i32;
}

/// Waits at most `limit` for the child; panics if it is still running.
fn finish_within(child: std::process::Child, limit: std::time::Duration) -> Output {
    let start = std::time::Instant::now();
    let mut child = child;
    while child.try_wait().unwrap().is_none() {
        if start.elapsed() > limit {
            let _ = child.kill();
            panic!("still running after {limit:?}");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    child.wait_with_output().unwrap()
}

#[test]
fn a_send_cancelled_while_its_stderr_is_held_elsewhere_still_ends() {
    let f = Fixture::new();
    let file = f.root.join("photo.jpg");
    std::fs::write(&file, "x").unwrap();
    let sender = f.root.join("sender");
    let child = spawn_with(
        &f,
        &["send", "--to", "e2:9d:03:6c:58:23", file.to_str().unwrap()],
        &[
            ("OMDROP_SENDER", sender.to_str().unwrap()),
            ("LINK_LOCAL", "1"),
            ("VISIBLE", "1"),
            ("HOLD_STDERR", "1"),
        ],
    );
    std::thread::sleep(std::time::Duration::from_millis(1500));
    signal(&child, 2);
    let out = finish_within(child, std::time::Duration::from_secs(3));
    assert_eq!(
        out.status.code(),
        Some(130),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("Cancelled."));
    // The sender was told which root helper `on` uses.
    let ev = std::fs::read_to_string(&f.capture).unwrap();
    assert!(
        ev.contains(&format!("sender-helper {}", f.helper.display())),
        "{ev}"
    );
    assert!(
        std::fs::read_dir(f.root.join("run/omdrop/sends"))
            .unwrap()
            .next()
            .is_none()
    );
}

#[test]
fn the_identity_step_leaves_the_root_helper_its_core_dumps() {
    let f = Fixture::new();
    let expected = Command::new("sh")
        .args(["-c", "ulimit -Hc"])
        .output()
        .unwrap();
    let expected = String::from_utf8_lossy(&expected.stdout).trim().to_string();
    // The real identity code, not identity.py.
    let (out, ev) = f.run(&["on", "once"], &[("OMDROP_IMPLEMENTATION", "")]);
    assert!(
        out.status.success(),
        "{}{ev}",
        String::from_utf8_lossy(&out.stderr)
    );
    let seen: Vec<&str> = ev
        .lines()
        .filter_map(|l| l.strip_prefix("pkexec-ulimit "))
        .collect();
    assert!(!seen.is_empty(), "{ev}");
    assert!(
        seen.iter().all(|s| *s == expected),
        "{seen:?} != {expected}"
    );
}

#[test]
fn a_start_cancelled_while_the_radio_comes_up_is_undone() {
    let f = Fixture::new();
    let child = spawn_with(&f, &["on", "10m"], &[("RADIO_SLEEP", "5")]);
    // Wait for the radio start to be under way.
    let start = std::time::Instant::now();
    while !std::fs::read_to_string(&f.capture)
        .unwrap()
        .contains(" start 600")
    {
        assert!(start.elapsed().as_secs() < 10, "the radio never started");
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    signal(&child, 15);
    let out = finish_within(child, std::time::Duration::from_secs(5));
    let ev = std::fs::read_to_string(&f.capture).unwrap();
    assert_eq!(out.status.code(), Some(130), "{ev}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("Cancelled."));
    let stop = format!("pkexec {} stop", f.helper.display());
    assert!(first(&ev, " start 600") < first(&ev, &stop), "{ev}");
    assert!(ev.contains("identity stop-end"), "{ev}");
    assert_eq!(ev.matches("stop omdrop-window.timer").count(), 2, "{ev}");
    assert!(!ev.contains("on-active"), "{ev}");
}

#[test]
fn a_plugin_outside_the_default_directory_is_found_again_by_what_omdrop_starts() {
    // The fixture's plugin is under the test root, not ~/.config/omarchy/plugins.
    let f = Fixture::new();
    let file = f.root.join("photo.jpg");
    std::fs::write(&file, "x").unwrap();
    let sender = f.root.join("sender");
    let (out, ev) = f.run(
        &["send", "Studio Mac", file.to_str().unwrap()],
        &[("OMDROP_SENDER", sender.to_str().unwrap())],
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(String::from_utf8_lossy(&out.stdout).contains("Turning it on"));
    assert!(!err.contains("cannot tell where it is installed"), "{err}");
    // The automatic `on` got as far as the receiver, and its units re-run
    // omdrop through the plugin's own command.
    assert!(ev.contains("--user start airdrop-receiver.service"), "{ev}");
    let watch = format!(
        "--unit=omdrop-watch {} watch --window 10m",
        f.omdrop.display()
    );
    assert!(ev.contains(&watch), "{ev}");
}

#[test]
fn core_run_directly_still_starts_everything_through_the_plugins_command() {
    // Core's own omdrop, run by its path rather than through the plugin's
    // bin/omdrop: the units still go through the plugin, the one entry point.
    let f = Fixture::new();
    let plugins = f.root.join("home/.config/omarchy/plugins");
    std::fs::create_dir_all(&plugins).unwrap();
    std::os::unix::fs::symlink(
        f.root.join("plugins/netmojo.omdrop"),
        plugins.join("netmojo.omdrop"),
    )
    .unwrap();
    let file = f.root.join("photo.jpg");
    std::fs::write(&file, "x").unwrap();
    let sender = f.root.join("sender");
    let out = f
        .command_as(
            Path::new(env!("CARGO_BIN_EXE_omdrop")),
            &["send", "Studio Mac", file.to_str().unwrap()],
        )
        .env("OMDROP_SENDER", &sender)
        .output()
        .unwrap();
    let ev = std::fs::read_to_string(&f.capture).unwrap();
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("Turning it on"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let watch = format!(
        "--unit=omdrop-watch {} watch --window 10m",
        plugins.join("netmojo.omdrop/bin/omdrop").display()
    );
    assert!(ev.contains(&watch), "{ev}");
    assert!(!ev.contains(env!("CARGO_BIN_EXE_omdrop")), "{ev}");
}

/// `handle` with a uwsm-app that keeps what it was given on stdin, the way
/// the real wl-copy behind it would read it.
fn handle_capturing_stdin(f: &Fixture, file: &Path, env: &[(&str, &str)]) -> (String, Vec<u8>) {
    let stdin = f.root.join("clipboard");
    write_exec(
        &f.root.join("bin/uwsm-app"),
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"uwsm-app $*\" >> \"$CAPTURE\"\ncat > '{}'\n",
            stdin.display()
        ),
    );
    let (out, ev) = f.run(&["handle", file.to_str().unwrap()], env);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    (ev, std::fs::read(&stdin).unwrap_or_default())
}

/// What the clipboard's decode left in the runtime dir. The toast's previews
/// have a directory of their own there, and their tests below.
fn clip_dirs_left(f: &Fixture) -> Vec<PathBuf> {
    std::fs::read_dir(f.root.join("run/omdrop"))
        .map(|d| {
            d.map(|e| e.unwrap().path())
                .filter(|p| !p.ends_with("previews"))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn a_heic_arrival_goes_on_the_clipboard_as_a_jpeg_and_leaves_nothing_behind() {
    // #62: since the receiver asks for original-format photos, iPhone photos
    // arrive as HEIC, which few applications can paste.
    if Command::new("heif-convert")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("heif-convert is not installed; the fallback test covers this host");
        return;
    }
    let f = Fixture::new();
    let photo = f.root.join("IMG_0001.HEIC");
    std::fs::copy(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/gradient.heic"),
        &photo,
    )
    .unwrap();
    let original = std::fs::read(&photo).unwrap();
    let (ev, clip) = handle_capturing_stdin(&f, &photo, &[]);
    assert!(ev.contains("uwsm-app -- wl-copy --type image/jpeg"), "{ev}");
    assert_eq!(
        &clip[..2],
        &[0xff, 0xd8],
        "not a JPEG: {:?}",
        &clip[..clip.len().min(8)]
    );
    assert_eq!(
        std::fs::read(&photo).unwrap(),
        original,
        "the arrival itself changed"
    );
    assert_eq!(clip_dirs_left(&f), Vec::<PathBuf>::new());
}

#[test]
fn a_heic_that_will_not_decode_goes_on_the_clipboard_as_its_path() {
    let f = Fixture::new();
    write_exec(&f.root.join("bin/heif-convert"), "#!/bin/sh\nexit 1\n");
    let photo = f.root.join("IMG_0002.heic");
    std::fs::write(&photo, "not really a heic").unwrap();
    let (ev, clip) = handle_capturing_stdin(&f, &photo, &[]);
    assert!(ev.contains("uwsm-app -- wl-copy\n"), "{ev}");
    assert_eq!(clip, photo.as_os_str().as_encoded_bytes());
    assert_eq!(clip_dirs_left(&f), Vec::<PathBuf>::new());
}

#[test]
fn a_heic_decode_that_hangs_is_cut_off_and_the_path_is_copied() {
    let f = Fixture::new();
    // Only the clipboard's decode hangs; the toast's preview has its own
    // limit, tested below, and fails at once here.
    write_exec(
        &f.root.join("bin/heif-convert"),
        "#!/bin/sh\ncase \"$4\" in */omdrop/previews/*) exit 1 ;; esac\nexec sleep 60\n",
    );
    let photo = f.root.join("IMG_0003.heic");
    std::fs::write(&photo, "slow").unwrap();
    let start = std::time::Instant::now();
    let (ev, clip) = handle_capturing_stdin(&f, &photo, &[]);
    let took = start.elapsed().as_secs();
    assert!((9..=20).contains(&took), "took {took} s");
    assert!(ev.contains("uwsm-app -- wl-copy\n"), "{ev}");
    assert_eq!(clip, photo.as_os_str().as_encoded_bytes());
    assert_eq!(clip_dirs_left(&f), Vec::<PathBuf>::new());
}

// ------------------------------------------------------- the toast (#57)
//
// The plugin's tests/test_notification.py and test_once_shutdown.py: an
// iPhone sends photos as HEIC, which the notification daemon cannot decode,
// so the toast gets a small JPEG preview, kept in the runtime dir and pruned.
// A click opens the file with its app, and shows it in the file manager only
// when no app is registered for its type -- otherwise xdg-open picks the
// browser.

/// heif-convert SRC DEST and magick SRC ... DEST: write something to DEST,
/// and log the call. magick's DEST carries a jpg: prefix.
const HEIF_CONVERT: &str = "printf 'heif-convert %s\\n' \"$*\" >> \"$CAPTURE\"\nfor a; do d=$a; done\nprintf jpeg > \"$d\"\n";
const MAGICK: &str = "printf 'magick %s\\n' \"$*\" >> \"$CAPTURE\"\nfor a; do d=$a; done\nprintf small > \"${d#jpg:}\"\n";

/// The click's world: only the stubs on PATH, so the host's own nautilus or
/// xdg-mime never answers. xdg-mime takes the type from the extension, and
/// only the types in MIME_DEFAULTS have an app; uwsm-app, the launch wrapper,
/// logs what it was asked to start.
fn click(f: &Fixture, file: &Path, nautilus: bool, xdg_mime: bool, defaults: &str) -> String {
    let bin = f.root.join("bin");
    write_exec(
        &bin.join("uwsm-app"),
        "#!/bin/sh\nprintf 'uwsm-app %s\\n' \"$*\" >> \"$CAPTURE\"\n",
    );
    if xdg_mime {
        write_exec(
            &bin.join("xdg-mime"),
            "#!/bin/sh\ncase \"$2\" in\n  filetype) case \"$3\" in *.heic) echo image/heic ;; *.jpg) echo image/jpeg ;; esac ;;\n  default) case \" $MIME_DEFAULTS \" in *\" $3 \"*) echo app.desktop ;; esac ;;\nesac\n",
        );
    } else {
        std::fs::remove_file(bin.join("xdg-mime")).unwrap();
    }
    if nautilus {
        write_exec(&bin.join("nautilus"), "#!/bin/sh\nexit 0\n");
    }
    std::fs::write(file, "photo").unwrap();
    let out = f
        .command(&["act", "open", file.to_str().unwrap()])
        .env("PATH", &bin)
        .env("MIME_DEFAULTS", defaults)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::read_to_string(&f.capture).unwrap()
}

#[test]
fn a_click_opens_a_file_that_has_an_app() {
    let f = Fixture::new();
    let photo = f.root.join("photo.jpg");
    let ev = click(&f, &photo, true, true, "image/jpeg");
    assert_eq!(ev, format!("uwsm-app -- xdg-open {}\n", photo.display()));
}

#[test]
fn a_click_shows_a_file_without_an_app_in_the_file_manager() {
    let f = Fixture::new();
    let photo = f.root.join("IMG_1.heic");
    let ev = click(&f, &photo, true, true, "image/jpeg");
    assert_eq!(
        ev,
        format!("uwsm-app -- nautilus --select {}\n", photo.display())
    );
}

#[test]
fn without_nautilus_a_click_opens_the_folder_instead() {
    let f = Fixture::new();
    let photo = f.root.join("IMG_1.heic");
    let ev = click(&f, &photo, false, true, "image/jpeg");
    assert_eq!(ev, format!("uwsm-app -- xdg-open {}\n", f.root.display()));
}

#[test]
fn a_click_opens_a_heic_once_an_app_is_registered_for_it() {
    let f = Fixture::new();
    let photo = f.root.join("IMG_1.heic");
    let ev = click(&f, &photo, true, true, "image/jpeg image/heic");
    assert_eq!(ev, format!("uwsm-app -- xdg-open {}\n", photo.display()));
}

#[test]
fn without_xdg_mime_a_click_opens_the_file_as_before() {
    let f = Fixture::new();
    let photo = f.root.join("IMG_1.heic");
    let ev = click(&f, &photo, true, false, "");
    assert_eq!(ev, format!("uwsm-app -- xdg-open {}\n", photo.display()));
}

/// A Fixture whose heif-convert and magick write stand-in images.
fn preview_fixture() -> Fixture {
    let f = Fixture::new();
    write_exec(
        &f.root.join("bin/heif-convert"),
        &format!("#!/bin/sh\n{HEIF_CONVERT}"),
    );
    write_exec(&f.root.join("bin/magick"), &format!("#!/bin/sh\n{MAGICK}"));
    f
}

fn previews(f: &Fixture) -> PathBuf {
    f.root.join("run/omdrop/previews")
}

fn previews_left(f: &Fixture) -> Vec<PathBuf> {
    let mut left: Vec<PathBuf> = std::fs::read_dir(previews(f))
        .map(|d| d.map(|e| e.unwrap().path()).collect())
        .unwrap_or_default();
    left.sort();
    left
}

/// `handle` a new arrival named NAME.
fn arrive(f: &Fixture, name: &str, env: &[(&str, &str)]) -> PathBuf {
    let photo = f.root.join(name);
    std::fs::write(&photo, "photo").unwrap();
    let (out, _) = f.run(&["handle", photo.to_str().unwrap()], env);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    photo
}

/// The toasts sent so far: each one's title and its --image, if any.
fn toasts(f: &Fixture) -> Vec<(String, Option<PathBuf>)> {
    std::fs::read_to_string(&f.capture)
        .unwrap()
        .lines()
        .filter_map(|l| l.strip_prefix("omarchy-notification-send "))
        .map(|l| {
            let words: Vec<&str> = l.split(' ').collect();
            let image = words
                .iter()
                .position(|w| *w == "--image")
                .map(|i| PathBuf::from(words[i + 1]));
            (words[2].to_string(), image)
        })
        .collect()
}

fn last_image(f: &Fixture) -> Option<PathBuf> {
    toasts(f).pop().expect("no toast").1
}

#[test]
fn a_heic_toast_carries_a_small_preview_in_the_runtime_dir() {
    use std::os::unix::fs::PermissionsExt;
    let f = preview_fixture();
    let photo = arrive(&f, "IMG_1.heic", &[]);
    let preview = last_image(&f).expect("no preview");
    assert_eq!(preview.parent(), Some(previews(&f).as_path()));
    let name = preview.file_name().unwrap().to_str().unwrap();
    assert!(
        name.starts_with("preview.") && name.ends_with(".jpg"),
        "{name}"
    );
    assert_eq!(std::fs::read(&preview).unwrap(), b"small");
    let ev = std::fs::read_to_string(&f.capture).unwrap();
    let decode = format!(
        "heif-convert -q 80 {} {}/working.",
        photo.display(),
        previews(&f).display()
    );
    assert!(ev.contains(&decode), "{ev}");
    assert!(ev.contains(" -thumbnail 512x512> -quality 80 jpg:"), "{ev}");
    let mode = std::fs::metadata(previews(&f))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o700);
    assert_eq!(previews_left(&f), vec![preview]);
}

#[test]
fn the_preview_stays_full_size_without_imagemagick() {
    let f = preview_fixture();
    write_exec(&f.root.join("bin/magick"), "#!/bin/sh\nexit 127\n");
    arrive(&f, "IMG_1.heic", &[]);
    let preview = last_image(&f).expect("no preview");
    assert_eq!(std::fs::read(&preview).unwrap(), b"jpeg");
    assert_eq!(previews_left(&f), vec![preview]);
}

#[test]
fn previews_of_the_same_name_do_not_overwrite_each_other() {
    let f = preview_fixture();
    arrive(&f, "IMG_1.heic", &[]);
    let first = last_image(&f).expect("no preview");
    arrive(&f, "IMG_1.avif", &[]);
    let second = last_image(&f).expect("no preview");
    assert_ne!(first, second);
    assert!(first.exists() && second.exists());
    assert_eq!(previews_left(&f).len(), 2);
}

#[test]
fn only_the_newest_previews_are_kept_and_nothing_else_is_touched() {
    let f = preview_fixture();
    std::fs::create_dir_all(previews(&f)).unwrap();
    let other = previews(&f).join("other.jpg");
    std::fs::write(&other, "mine").unwrap();
    std::fs::File::options()
        .write(true)
        .open(&other)
        .unwrap()
        .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(3600))
        .unwrap();
    for n in 0..12 {
        arrive(&f, &format!("IMG_{n}.heic"), &[]);
        // Distinct mtimes, so the newest are unambiguous.
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let kept: Vec<PathBuf> = previews_left(&f)
        .into_iter()
        .filter(|p| *p != other)
        .collect();
    assert_eq!(kept.len(), 10, "{kept:?}");
    let images: Vec<PathBuf> = toasts(&f).into_iter().filter_map(|t| t.1).collect();
    assert_eq!(images.len(), 12);
    for (n, image) in images.iter().enumerate() {
        assert_eq!(kept.contains(image), n >= 2, "toast {n}: {image:?}");
    }
    assert!(other.exists());
}

#[test]
fn a_preview_still_being_decoded_survives_other_arrivals() {
    // Arrivals are handled in parallel. One photo's preview decodes slowly
    // while eleven others arrive and finish; their pruning must not delete
    // the file the slow decode has already written into.
    let f = preview_fixture();
    write_exec(
        &f.root.join("bin/heif-convert"),
        &format!(
            "#!/bin/sh\n{HEIF_CONVERT}case \"$3$4\" in *SLOW*/omdrop/previews/*) sleep 2 ;; esac\n"
        ),
    );
    let slow = f.root.join("SLOW.heic");
    std::fs::write(&slow, "photo").unwrap();
    let decoding = spawn_with(&f, &["handle", slow.to_str().unwrap()], &[]);
    std::thread::sleep(std::time::Duration::from_millis(500));
    for n in 0..11 {
        arrive(&f, &format!("IMG_{n}.heic"), &[]);
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let out = finish_within(decoding, std::time::Duration::from_secs(30));
    assert!(out.status.success());
    let (_, image) = toasts(&f)
        .into_iter()
        .find(|t| t.0 == "SLOW.heic")
        .expect("no toast for the slow photo");
    let image = image.expect("the slow photo's toast lost its preview");
    assert!(image.exists());
    assert_eq!(image.parent(), Some(previews(&f).as_path()));
}

#[test]
fn a_preview_whose_shrink_timed_out_survives_newer_previews() {
    // A shrink that times out leaves the decode's older time on the preview,
    // and ten newer previews finish meanwhile; pruning must still keep the
    // preview this toast is about to show.
    let f = preview_fixture();
    write_exec(
        &f.root.join("bin/heif-convert"),
        "#!/bin/sh\nfor a; do d=$a; done\ncase \"$*\" in *SLOW*) printf slow > \"$d\" ;; *) printf jpeg > \"$d\" ;; esac\n",
    );
    write_exec(
        &f.root.join("bin/magick"),
        &format!("#!/bin/sh\ncase \"$(cat \"$1\")\" in slow) exec sleep 30 ;; esac\n{MAGICK}"),
    );
    let slow = f.root.join("SLOW.heic");
    std::fs::write(&slow, "photo").unwrap();
    let mut decoding = spawn_with(
        &f,
        &["handle", slow.to_str().unwrap()],
        &[("OMDROP_PREVIEW_TIMEOUT", "5")],
    );
    std::thread::sleep(std::time::Duration::from_millis(500));
    for n in 0..10 {
        arrive(&f, &format!("IMG_{n}.heic"), &[]);
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(
        decoding.try_wait().unwrap().is_none(),
        "the slow shrink ended before the others finished"
    );
    let out = finish_within(decoding, std::time::Duration::from_secs(30));
    assert!(out.status.success());
    let (_, image) = toasts(&f)
        .into_iter()
        .find(|t| t.0 == "SLOW.heic")
        .expect("no toast for the slow photo");
    let image = image.expect("the slow photo's toast lost its preview");
    assert!(image.exists(), "pruned before its toast showed it");
}

#[test]
fn a_preview_left_behind_by_a_killed_decode_is_cleaned_up() {
    let f = preview_fixture();
    std::fs::create_dir_all(previews(&f)).unwrap();
    let stale = previews(&f).join("working.Old456.jpg");
    let fresh = previews(&f).join("working.New789.jpg");
    std::fs::write(&stale, "half").unwrap();
    std::fs::write(&fresh, "half").unwrap();
    std::fs::File::options()
        .write(true)
        .open(&stale)
        .unwrap()
        .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(600))
        .unwrap();
    arrive(&f, "IMG_9.heic", &[]);
    assert!(!stale.exists());
    assert!(fresh.exists(), "a decode still in progress lost its file");
}

#[test]
fn a_heic_toast_still_appears_when_the_conversion_fails() {
    let f = preview_fixture();
    // A multi-image file's outputs beside the target, then a failure.
    write_exec(
        &f.root.join("bin/heif-convert"),
        "#!/bin/sh\nprintf x > \"${4%.jpg}-1.jpg\"\nexit 1\n",
    );
    arrive(&f, "IMG_2.heic", &[]);
    let toasts = toasts(&f);
    assert_eq!(toasts.len(), 1);
    assert_eq!(toasts[0].1, None);
    assert_eq!(previews_left(&f), Vec::<PathBuf>::new());
}

#[test]
fn a_conversion_that_hangs_is_cut_off_with_everything_it_started() {
    // Only the preview's decode hangs. The clipboard's own HEIC-to-JPEG
    // decode (#62) has a fixed 10 s limit of its own, which this test does
    // not measure, so it fails at once.
    let f = preview_fixture();
    let pid_file = f.root.join("sleeper");
    write_exec(
        &f.root.join("bin/heif-convert"),
        &format!(
            "#!/bin/sh\ncase \"$4\" in */omdrop/previews/*) sleep 30 & echo $! > '{}'; wait ;; esac\nexit 1\n",
            pid_file.display()
        ),
    );
    let start = std::time::Instant::now();
    arrive(&f, "IMG_3.heic", &[("OMDROP_PREVIEW_TIMEOUT", "1")]);
    assert!(
        start.elapsed() < std::time::Duration::from_secs(10),
        "took {:?}",
        start.elapsed()
    );
    let toasts = toasts(&f);
    assert_eq!(toasts.len(), 1);
    assert_eq!(toasts[0].1, None);
    assert_eq!(previews_left(&f), Vec::<PathBuf>::new());
    // The decoder's own child went with it.
    let pid = std::fs::read_to_string(&pid_file).unwrap();
    let stat = format!("/proc/{}/stat", pid.trim());
    let gone = (0..20).any(|_| {
        let state = std::fs::read_to_string(&stat).unwrap_or_default();
        let dead = state
            .rsplit_once(") ")
            .is_none_or(|(_, rest)| rest.starts_with('Z'));
        if !dead {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        dead
    });
    assert!(gone, "the decoder's child outlived the cut-off");
}

#[test]
fn a_jpeg_toast_uses_the_file_itself() {
    let f = preview_fixture();
    let photo = arrive(&f, "photo.jpg", &[]);
    assert_eq!(last_image(&f), Some(photo));
    let ev = std::fs::read_to_string(&f.capture).unwrap();
    assert!(!ev.contains("heif-convert"), "{ev}");
}

#[test]
fn the_notification_outlives_the_watcher_too() {
    // `handle` decodes a HEIC preview before it notifies. Inside the
    // watcher's cgroup, the close that follows a one-file window killed it,
    // and the photo arrived with no notification at all.
    let f = Fixture::new();
    let file = arrival(&f, "arrived.jpg");
    let journal = format!("{TS}upload ABC: stored arrived.jpg");
    let (out, ev) = f.run(&["watch", "--once"], &[("JOURNAL", &journal)]);
    assert!(out.status.success());
    let unit = format!(
        "systemd-run --user --quiet --collect {} handle {}",
        f.omdrop.display(),
        file.display()
    );
    assert!(ev.lines().any(|l| l == unit), "{ev}");
    assert!(!ev.contains("omarchy-notification-send"), "{ev}");
}

#[test]
fn without_systemd_run_the_close_waits_for_the_notification() {
    // handle then runs inside the watcher, and the close would kill it.
    let f = Fixture::new();
    write_exec(
        &f.root.join("bin/systemd-run"),
        "#!/bin/sh\nprintf 'systemd-run %s\\n' \"$*\" >> \"$CAPTURE\"\ncase \"$*\" in *\" handle \"*) exit 1 ;; esac\nexit 0\n",
    );
    // The toast takes a moment, so a close that does not wait for it is
    // logged first.
    write_exec(
        &f.root.join("bin/omarchy-notification-send"),
        "#!/bin/sh\nsleep 1\nprintf 'omarchy-notification-send %s\\n' \"$*\" >> \"$CAPTURE\"\n",
    );
    arrival(&f, "arrived.jpg");
    let journal = format!("{TS}upload ABC: stored arrived.jpg");
    let (out, ev) = f.run(&["watch", "--once"], &[("JOURNAL", &journal)]);
    assert!(out.status.success());
    assert!(
        first(&ev, "omarchy-notification-send") < first(&ev, " off --force"),
        "{ev}"
    );
}

// ------------------------------------------------------------ radio backends
//
// The plugin's tests/test_radio_backend.py: a helper may answer `probe
// --json` (docs/radio-backend.md); when it does, the hardware and install
// checks are the backend's, so a machine without Apple's Broadcom Wi-Fi is
// not refused out of hand. A helper that does not answer gets the Broadcom
// checks exactly as before.

const BROADCOM_SAYS: &str = "no Apple Broadcom Wi-Fi";

/// The plugin tests' `helper()`: an omdrop-discoverable that answers probe
/// with PROBE, or, given `None`, behaves like omdrop-awdl's: usage and exit
/// 2 for a subcommand it does not know.
fn backend_helper(probe: Option<serde_json::Value>) -> String {
    match probe {
        None => "#!/bin/sh\necho \"usage: omdrop-discoverable start|stop|status\" >&2\nexit 2\n"
            .to_string(),
        Some(p) => format!("#!/bin/sh\n[ \"$1\" = probe ] || exit 2\ncat <<'EOF'\n{p}\nEOF\n"),
    }
}

/// A helper whose probe never answers. The child sleep keeps stdout open
/// after the shell is killed, which is what a hung helper usually looks like.
const HUNG: &str = "#!/bin/sh\n[ \"$1\" = probe ] || exit 2\nsleep 30\necho \"{}\"\n";

fn owl(missing: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "backend": "owl", "version": "0.1.0", "hardware": true, "contract": "0.7.0",
        "missing": missing,
    })
}

struct Radio {
    f: Fixture,
    env: Vec<(String, String)>,
}

impl Radio {
    /// A machine with no PCI network hardware at all: not a Mac. The
    /// receiver's service is installed, nothing is active (ufw included),
    /// no driver package is installed, and the install terminal only shows
    /// what it was given.
    fn new() -> Self {
        let f = Fixture::new();
        let sys = f.root.join("sys");
        std::fs::create_dir_all(sys.join("bus/pci/devices")).unwrap();
        write_exec(
            &f.root.join("bin/systemctl"),
            "#!/bin/sh\ncase \"$*\" in *is-active*) exit 3 ;; esac\nexit 0\n",
        );
        write_exec(&f.root.join("bin/pacman"), "#!/bin/sh\nexit 1\n");
        write_exec(
            &f.root
                .join("bin/omarchy-launch-floating-terminal-with-presentation"),
            "#!/bin/sh\nprintf '%s\\n' \"$1\"\n",
        );
        // UFW's own files are the test's: enforcing, dropping incoming
        // traffic by default, and no rules file, so whether the rule is there
        // can't be told until a test writes one.
        let etc = f.root.join("etc");
        std::fs::create_dir_all(etc.join("ufw")).unwrap();
        std::fs::create_dir_all(etc.join("default")).unwrap();
        std::fs::write(etc.join("ufw/ufw.conf"), "ENABLED=yes\nLOGLEVEL=low\n").unwrap();
        std::fs::write(
            etc.join("default/ufw"),
            "IPV6=yes\nDEFAULT_INPUT_POLICY=\"DROP\"\n",
        )
        .unwrap();
        let env = vec![
            ("OMDROP_SYSFS".to_string(), sys.display().to_string()),
            ("OMDROP_UFW_ETC".to_string(), etc.display().to_string()),
        ];
        Self { f, env }
    }

    fn helper(&self, body: &str) {
        write_exec(&self.f.helper, body);
    }

    fn set(&mut self, k: &str, v: &str) {
        self.env.push((k.to_string(), v.to_string()));
    }

    /// A libarchive without the API the receiver calls, ahead of the real
    /// one, is what "not installed" looks like to the Python receiver's check.
    fn without_receiver_library(&mut self) {
        let fake = self.f.root.join("py/libarchive");
        std::fs::create_dir_all(&fake).unwrap();
        std::fs::write(fake.join("__init__.py"), "").unwrap();
        let py = self.f.root.join("py").display().to_string();
        self.set("PYTHONPATH", &py);
    }

    fn run(&self, args: &[&str]) -> Output {
        let env: Vec<(&str, &str)> = self
            .env
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        self.f.run(args, &env).0
    }

    fn doctor(&self) -> serde_json::Value {
        let out = self.run(&["doctor", "--json"]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        serde_json::from_slice(&out.stdout).unwrap()
    }

    fn ids(&self) -> Vec<String> {
        self.doctor()["missing"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["id"].as_str().unwrap().to_string())
            .collect()
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// What the Python receiver's library check sees on this machine.
fn receiver_libs_here() -> bool {
    Command::new("/usr/bin/python3")
        .args([
            "-c",
            "from libarchive import stream_reader; import ctypes; ctypes.CDLL(\"libkeyutils.so.1\")",
        ])
        .output()
        .is_ok_and(|o| o.status.success())
}

#[test]
fn a_probing_backend_owns_the_hardware_check() {
    let r = Radio::new();
    r.helper(&backend_helper(Some(owl(serde_json::json!([
        {"id": "radio", "say": "Wi-Fi is not connected."}
    ])))));
    let missing = r.doctor()["missing"].clone();
    assert_eq!(
        missing[0],
        serde_json::json!({"id": "radio", "say": "Wi-Fi is not connected."})
    );
    assert!(!missing.to_string().contains(BROADCOM_SAYS), "{missing}");
}

#[test]
fn a_ready_backend_leaves_only_the_plugins_own_findings() {
    let r = Radio::new();
    r.helper(&backend_helper(Some(owl(serde_json::json!([])))));
    let doctor = r.doctor();
    let ids: Vec<&str> = doctor["missing"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_str().unwrap())
        .collect();
    assert!(ids.iter().all(|i| *i == "library"), "{doctor}");
    if receiver_libs_here() {
        assert_eq!(
            doctor,
            serde_json::json!({"ready": true, "missing": [], "offers": []})
        );
        let out = r.run(&["doctor"]);
        assert!(
            text(&out.stdout).starts_with("Ready to receive.\n"),
            "{}",
            text(&out.stdout)
        );
    }
}

/// The plugin carries omdrop-core 0.2.0-1; pacman reports `installed`.
fn with_core(r: &Radio, installed: &str) {
    let core = r.f.root.join("plugins/netmojo.omdrop/core");
    std::fs::create_dir_all(&core).unwrap();
    std::fs::write(
        core.join("PKGBUILD"),
        "pkgname=omdrop-core\npkgver=0.2.0\npkgrel=1\n",
    )
    .unwrap();
    write_exec(
        &r.f.root.join("bin/pacman"),
        &format!(
            "#!/bin/sh\n[ \"$1 $2\" = '-Q omdrop-core' ] || exit 1\necho 'omdrop-core {installed}'\n"
        ),
    );
}

fn awdl() -> serde_json::Value {
    serde_json::json!({
        "backend": "awdl", "version": "0.10.0", "hardware": true, "contract": "0.7.0",
        "missing": [],
    })
}

#[test]
fn an_installed_core_older_than_the_plugins_is_offered_an_update() {
    let r = Radio::new();
    r.helper(&backend_helper(Some(awdl())));
    with_core(&r, "0.1.0-1");
    let doctor = r.doctor();
    let offers = doctor["offers"].as_array().unwrap();
    assert_eq!(offers.len(), 1, "{doctor}");
    assert_eq!(offers[0]["id"], "core");
    let say = offers[0]["say"].as_str().unwrap();
    assert!(
        say.contains("0.1.0-1") && say.contains("0.2.0-1") && say.contains("omdrop install-core"),
        "{say}"
    );
    assert!(!r.ids().contains(&"core".to_string()), "{doctor}");
    let out = text(&r.run(&["doctor"]).stdout);
    assert!(out.contains("\nTo do:\n  - omdrop-core 0.1.0-1"), "{out}");
}

#[test]
fn a_current_core_or_an_untested_backend_is_offered_nothing() {
    let mut no_hardware = awdl();
    no_hardware["hardware"] = serde_json::json!(false);
    for (backend, installed) in [
        (awdl(), "0.2.0-1"),
        (owl(serde_json::json!([])), "0.1.0-1"),
        (no_hardware, "0.1.0-1"),
    ] {
        let r = Radio::new();
        r.helper(&backend_helper(Some(backend.clone())));
        with_core(&r, installed);
        assert_eq!(
            r.doctor()["offers"],
            serde_json::json!([]),
            "{backend} {installed}"
        );
    }
}

/// One installer: core hands `install-core` to the plugin's own bin/omdrop,
/// run as the Python version so it does not hand straight back.
#[test]
fn install_core_runs_the_plugins_installer() {
    let tmp = tempfile::tempdir().unwrap();
    let plugin = tmp.path().join("config/omarchy/plugins/netmojo.omdrop");
    std::fs::create_dir_all(plugin.join("bin")).unwrap();
    std::fs::write(plugin.join("manifest.json"), r#"{"version": "9.9.9"}"#).unwrap();
    let record = tmp.path().join("ran");
    write_exec(
        &plugin.join("bin/omdrop"),
        &format!(
            "#!/bin/sh\necho \"$* $OMDROP_IMPLEMENTATION\" > '{}'\nexit 7\n",
            record.display()
        ),
    );
    let out = Command::new(env!("CARGO_BIN_EXE_omdrop"))
        .arg("install-core")
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", tmp.path())
        .env("XDG_CONFIG_HOME", tmp.path().join("config"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(7), "{}", text(&out.stderr));
    assert_eq!(
        std::fs::read_to_string(&record).unwrap(),
        "install-core python\n"
    );
}

#[test]
fn hardware_the_backend_cannot_drive_is_reported_alone() {
    let mut r = Radio::new();
    r.helper(&backend_helper(Some(serde_json::json!({
        "backend": "owl", "version": "0.1.0", "hardware": false,
        "missing": [{"id": "hardware", "say": "No supported Wi-Fi card."},
                    {"id": "radio", "say": "never shown"}]
    }))));
    r.without_receiver_library();
    assert_eq!(
        r.doctor()["missing"],
        serde_json::json!([{"id": "hardware", "say": "No supported Wi-Fi card."}])
    );
    // One that names no hardware item gets the plugin's sentence for it.
    r.helper(&backend_helper(Some(
        serde_json::json!({"backend": "owl", "hardware": false}),
    )));
    assert_eq!(
        r.doctor()["missing"],
        serde_json::json!([{"id": "hardware", "say": "This computer's Wi-Fi is not one the installed radio backend (owl) can drive."}])
    );
}

#[test]
fn a_helper_without_probe_gets_the_broadcom_checks() {
    let r = Radio::new();
    r.helper(&backend_helper(None));
    let doctor = r.doctor();
    assert_eq!(r.ids(), ["hardware"]);
    assert_eq!(
        doctor["missing"][0]["say"],
        "This computer has no Apple Broadcom Wi-Fi, which Omdrop's own driver needs: it runs only on Apple Silicon Macs, not in a virtual machine. Other Wi-Fi cards need a different radio backend (docs/radio-backend.md)."
    );
    // On a Mac the hardware item goes and the driver's own checks remain.
    on_a_mac(&r);
    let ids = r.ids();
    assert!(
        ids.iter()
            .all(|i| ["library", "radio", "service"].contains(&i.as_str())),
        "{ids:?}"
    );
}

#[test]
fn an_answer_without_a_backend_name_is_not_a_probe() {
    let r = Radio::new();
    for probe in [
        serde_json::json!({"visible": true}),
        serde_json::json!({"backend": "  "}),
        serde_json::json!(["owl"]),
    ] {
        r.helper(&backend_helper(Some(probe.clone())));
        let doctor = r.doctor();
        assert!(
            doctor["missing"][0]["say"]
                .as_str()
                .unwrap()
                .contains(BROADCOM_SAYS),
            "{probe}: {doctor}"
        );
    }
    // Nor is a probe that fails, whatever it printed.
    r.helper("#!/bin/sh\necho '{\"backend\": \"owl\"}'\nexit 1\n");
    assert_eq!(r.ids(), ["hardware"]);
}

#[test]
fn a_backend_below_the_minimum_contract_is_a_blocker_that_names_it() {
    let r = Radio::new();
    for contract in [Some("0.1.0"), None] {
        let mut probe = owl(serde_json::json!([]));
        match contract {
            Some(c) => probe["contract"] = c.into(),
            None => {
                probe.as_object_mut().unwrap().remove("contract");
            }
        }
        r.helper(&backend_helper(Some(probe)));
        let first = r.doctor()["missing"][0].clone();
        assert_eq!(first["id"], "backend", "{contract:?}");
        assert_eq!(
            first["say"],
            format!(
                "The installed radio backend (owl) follows helper contract {}, older than the 0.7.0 this version of Omdrop needs. Update its package.",
                contract.unwrap_or("none")
            )
        );
    }
}

#[test]
fn a_backend_cannot_claim_the_ids_the_panel_acts_on() {
    let r = Radio::new();
    let mut probe = owl(serde_json::json!([
        {"id": "driver", "say": "The OWL daemon\n  is missing."},
        {"id": "radio", "say": "Wi-Fi is not connected."},
        {"id": "", "say": "no id"},
        {"id": "x"},
        "not an item"
    ]));
    probe["contract"] = "0.8.1".into();
    r.helper(&backend_helper(Some(probe)));
    let doctor = r.doctor();
    let ids = r.ids();
    assert_eq!(ids[..2], ["backend-driver", "radio"], "{doctor}");
    assert!(!ids.contains(&"driver".to_string()), "{ids:?}");
    assert!(ids[2..].iter().all(|i| i == "library"), "{ids:?}");
    assert_eq!(doctor["missing"][0]["say"], "The OWL daemon is missing.");
}

#[test]
fn a_probe_that_hangs_is_the_backends_problem_not_a_missing_mac() {
    let mut r = Radio::new();
    r.helper(HUNG);
    r.set("OMDROP_PROBE_TIMEOUT", "1");
    let start = std::time::Instant::now();
    let missing = r.doctor()["missing"].clone();
    assert!(start.elapsed() < std::time::Duration::from_secs(10));
    assert_eq!(missing[0]["id"], "backend");
    let say = missing[0]["say"].as_str().unwrap();
    assert!(
        say.starts_with("The radio backend did not answer when asked what it needs (")
            && say.ends_with(
                "omdrop-discoverable probe, 1 seconds). Reinstalling or updating its package may help."
            ),
        "{say}"
    );
    assert!(!missing.to_string().contains(BROADCOM_SAYS), "{missing}");
}

#[test]
fn a_probe_that_hangs_offers_no_install_button() {
    // install-driver refuses for a backend that does not answer, so the
    // library item, which brings up the panel's button, stays out.
    let mut r = Radio::new();
    r.helper("#!/bin/sh\n[ \"$1\" = probe ] || exit 2\nsleep 30\n");
    r.set("OMDROP_PROBE_TIMEOUT", "1");
    r.without_receiver_library();
    assert_eq!(r.ids(), ["backend"]);
}

#[test]
fn install_with_a_probing_backend_never_builds_the_broadcom_driver() {
    let mut r = Radio::new();
    r.helper(&backend_helper(Some(owl(serde_json::json!([])))));
    r.without_receiver_library();
    let out = r.run(&["install-driver"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert!(
        stdout.starts_with("Opening a terminal to install what the receiver needs.\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains("pacman -S --needed --asdeps python-libarchive-c keyutils"),
        "{stdout}"
    );
    for broadcom in ["brcmfmac-awdl-dkms", "makepkg", "omdrop-awdl"] {
        assert!(!stdout.contains(broadcom), "{broadcom}: {stdout}");
    }
}

#[test]
fn install_with_a_probing_backend_and_nothing_missing_does_nothing() {
    let r = Radio::new();
    r.helper(&backend_helper(Some(owl(serde_json::json!([])))));
    let out = r.run(&["install-driver"]);
    if !receiver_libs_here() {
        eprintln!("this machine lacks the receiver's packages; covered above");
        return;
    }
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        text(&out.stdout),
        "The receiver's packages are installed and the radio comes from owl 0.1.0. Nothing to do.\n"
    );
}

#[test]
fn install_for_a_backend_below_the_contract_still_installs_the_receiver() {
    let mut r = Radio::new();
    let mut probe = owl(serde_json::json!([]));
    probe["contract"] = "0.6.0".into();
    r.helper(&backend_helper(Some(probe)));
    r.without_receiver_library();
    let out = r.run(&["install-driver"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        text(&out.stderr),
        "The installed radio backend (owl) follows helper contract 0.6.0, older than the 0.7.0 this version of Omdrop needs. Update its package.\n"
    );
    assert!(text(&out.stdout).contains("--asdeps python-libarchive-c keyutils"));
}

#[test]
fn install_refuses_when_the_probe_hangs() {
    let mut r = Radio::new();
    r.helper("#!/bin/sh\n[ \"$1\" = probe ] || exit 2\nsleep 30\n");
    r.set("OMDROP_PROBE_TIMEOUT", "1");
    let out = r.run(&["install-driver"]);
    assert_ne!(out.status.code(), Some(0));
    assert!(
        text(&out.stderr).contains("did not answer"),
        "{}",
        text(&out.stderr)
    );
    let stdout = text(&out.stdout);
    for broadcom in ["brcmfmac-awdl-dkms", "makepkg", "omdrop-awdl"] {
        assert!(!stdout.contains(broadcom), "{broadcom}: {stdout}");
    }
}

#[test]
fn install_without_a_probe_still_refuses_a_machine_with_no_broadcom() {
    let r = Radio::new();
    r.helper(&backend_helper(None));
    let out = r.run(&["install-driver"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains(BROADCOM_SAYS),
        "{}",
        text(&out.stderr)
    );
}

// omdrop-awdl 0.10.0 answers probe through its hooks as backend `awdl`, but
// it is still the Broadcom driver install-driver builds: its version is
// checked against the pin, and install-driver updates it.

/// pacman with brcmfmac-awdl-dkms at `installed`, or without it, and no
/// repository that carries it.
fn with_driver(r: &Radio, installed: Option<&str>) {
    let answer = match installed {
        Some(v) => format!("echo 'brcmfmac-awdl-dkms {v}'"),
        None => "exit 1".to_string(),
    };
    write_exec(
        &r.f.root.join("bin/pacman"),
        &format!("#!/bin/sh\n[ \"$1 $2\" = '-Q brcmfmac-awdl-dkms' ] || exit 1\n{answer}\n"),
    );
}

fn awdl_hooks(missing: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "backend": "awdl", "version": "0.10.0", "contract": "0.10.0", "hooks": 1,
        "hardware": true, "missing": missing,
    })
}

const AWDL_RADIO: &str = "AirDrop's Wi-Fi driver is not loaded. Restart to load it.";

#[test]
fn awdl_with_an_outdated_driver_offers_install_driver_which_builds_it() {
    let r = Radio::new();
    r.helper(&backend_helper(Some(awdl_hooks(serde_json::json!([
        {"id": "radio", "say": AWDL_RADIO}
    ])))));
    with_driver(&r, Some("0.9.0-1"));
    let doctor = r.doctor();
    assert_eq!(
        doctor["missing"].as_array().unwrap()[..2],
        [
            serde_json::json!({"id": "driver", "say": "The Wi-Fi driver is older than the 0.10.0 this version of Omdrop needs (installed: 0.9.0-1). Update it with: omdrop install-driver"}),
            serde_json::json!({"id": "radio", "say": AWDL_RADIO}),
        ],
        "{doctor}"
    );
    assert!(!doctor.to_string().contains(BROADCOM_SAYS), "{doctor}");

    let out = r.run(&["install-driver"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert!(
        stdout.starts_with("Opening a terminal to install the driver.\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains("omdrop-awdl.git") && stdout.contains("&& makepkg"),
        "{stdout}"
    );

    // A driver pacman does not know is no newer.
    with_driver(&r, None);
    assert_eq!(
        r.doctor()["missing"][0]["say"],
        "The Wi-Fi driver is older than the 0.10.0 this version of Omdrop needs (installed: none). Update it with: omdrop install-driver"
    );
}

#[test]
fn awdl_with_a_current_driver_has_nothing_to_install() {
    let mut r = Radio::new();
    r.helper(&backend_helper(Some(awdl_hooks(serde_json::json!([])))));
    with_driver(&r, Some("0.10.0-1"));
    assert!(!r.ids().contains(&"driver".to_string()), "{}", r.doctor());
    let out = r.run(&["install-driver"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    if receiver_libs_here() {
        assert_eq!(
            text(&out.stdout),
            "The driver and the Python library the receiver needs are both installed and current. Nothing to do.\n"
        );
    }
    // Missing receiver packages are installed without rebuilding the driver.
    r.without_receiver_library();
    let out = r.run(&["install-driver"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert!(
        stdout.starts_with("Opening a terminal to install the driver.\n")
            && stdout.contains("pacman -S --needed --asdeps python-libarchive-c keyutils"),
        "{stdout}"
    );
    for driver in ["brcmfmac-awdl-dkms", "makepkg", "omdrop-awdl"] {
        assert!(!stdout.contains(driver), "{driver}: {stdout}");
    }
}

#[test]
fn awdl_on_hardware_it_cannot_drive_is_refused_alone() {
    let mut r = Radio::new();
    let mut probe = awdl_hooks(serde_json::json!([
        {"id": "hardware", "say": "This computer has no Apple Broadcom Wi-Fi."},
        {"id": "radio", "say": AWDL_RADIO}
    ]));
    probe["hardware"] = false.into();
    r.helper(&backend_helper(Some(probe)));
    with_driver(&r, Some("0.9.0-1"));
    r.without_receiver_library();
    assert_eq!(
        r.doctor()["missing"],
        serde_json::json!([{"id": "hardware", "say": "This computer has no Apple Broadcom Wi-Fi."}])
    );
    let out = r.run(&["install-driver"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        text(&out.stderr),
        "This computer has no Apple Broadcom Wi-Fi.\n"
    );
    assert_eq!(text(&out.stdout), "");
}

/// UFW installed and its service active.
fn with_ufw_active(r: &Radio) {
    write_exec(&r.f.root.join("bin/ufw"), "#!/bin/sh\nexit 0\n");
    write_exec(&r.f.root.join("bin/systemctl"), "#!/bin/sh\nexit 0\n");
}

/// Apple's Broadcom Wi-Fi on PCI.
fn on_a_mac(r: &Radio) {
    let dev = r.f.root.join("sys/bus/pci/devices/0000:01:00.0");
    std::fs::create_dir_all(&dev).unwrap();
    std::fs::write(dev.join("vendor"), "0x14e4\n").unwrap();
    std::fs::write(dev.join("class"), "0x028000\n").unwrap();
}

/// With the driver current, install-driver still adds the firewall rule
/// while UFW is active, and builds nothing.
fn assert_installs_only_the_firewall_rule(r: &Radio) {
    let out = r.run(&["install-driver"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert!(stdout.contains(" firewall install"), "{stdout}");
    for driver in ["brcmfmac-awdl-dkms", "makepkg", "omdrop-awdl"] {
        assert!(!stdout.contains(driver), "{driver}: {stdout}");
    }
    assert!(!stdout.contains("Nothing to do"), "{stdout}");
    if receiver_libs_here() {
        assert!(
            stdout.starts_with("Opening a terminal to add the firewall rule the receiver needs.\n"),
            "{stdout}"
        );
        assert!(!stdout.contains("pacman"), "{stdout}");
    }
}

#[test]
fn a_current_awdl_driver_still_gets_the_firewall_rule_while_ufw_is_active() {
    let r = Radio::new();
    r.helper(&backend_helper(Some(awdl_hooks(serde_json::json!([])))));
    with_driver(&r, Some("0.10.0-1"));
    with_ufw_active(&r);
    assert_installs_only_the_firewall_rule(&r);
}

#[test]
fn a_current_driver_without_a_probe_still_gets_the_firewall_rule_while_ufw_is_active() {
    let r = Radio::new();
    r.helper(&backend_helper(None));
    on_a_mac(&r);
    with_driver(&r, Some("0.10.0-1"));
    with_ufw_active(&r);
    assert_installs_only_the_firewall_rule(&r);
}

#[test]
fn a_current_driver_with_ufw_inactive_has_nothing_to_do() {
    if !receiver_libs_here() {
        eprintln!("this machine lacks the receiver's packages; nothing would be current");
        return;
    }
    for probe in [None, Some(awdl_hooks(serde_json::json!([])))] {
        let r = Radio::new();
        r.helper(&backend_helper(probe.clone()));
        on_a_mac(&r);
        with_driver(&r, Some("0.10.0-1"));
        write_exec(&r.f.root.join("bin/ufw"), "#!/bin/sh\nexit 0\n");
        let out = r.run(&["install-driver"]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        assert_eq!(
            text(&out.stdout),
            "The driver and the Python library the receiver needs are both installed and current. Nothing to do.\n",
            "{probe:?}"
        );
    }
}

/// The receiver's rule as `ufw` writes it into user6.rules, comment and all.
const RECEIVER_TUPLE: &str = "### tuple ### allow tcp 8771 fe80::/10 any fe80::/10 in_awdl0 comment=4f6d64726f702041697244726f70207265636569766572";
const SSH_TUPLE: &str = "### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in";

fn ufw_rules(r: &Radio, tuples: &[&str]) {
    let mut text = String::from("*filter\n");
    for t in tuples {
        text.push_str(t);
        text.push('\n');
    }
    text.push_str("COMMIT\n");
    std::fs::write(r.f.root.join("etc/ufw/user6.rules"), text).unwrap();
}

/// A radio backend with nothing missing, and UFW on: the plugin's own items
/// are all doctor can report.
fn ready_owl_behind_ufw() -> Radio {
    let r = Radio::new();
    r.helper(&backend_helper(Some(owl(serde_json::json!([])))));
    with_ufw_active(&r);
    r
}

#[test]
fn ufw_enforcing_without_the_receivers_rule_is_reported_last() {
    let r = ready_owl_behind_ufw();
    ufw_rules(&r, &[SSH_TUPLE]);
    let doctor = r.doctor();
    let last = doctor["missing"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    assert_eq!(last["id"], "firewall");
    assert!(
        last["say"]
            .as_str()
            .unwrap()
            .contains("Apple devices can find this computer but not connect"),
        "{last}"
    );
}

#[test]
fn the_firewall_is_reported_only_when_ufw_certainly_drops_the_receiver() {
    let rule_there = ready_owl_behind_ufw();
    ufw_rules(&rule_there, &[SSH_TUPLE, RECEIVER_TUPLE]);
    let unreadable = ready_owl_behind_ufw();
    let no_policy = ready_owl_behind_ufw();
    ufw_rules(&no_policy, &[SSH_TUPLE]);
    std::fs::remove_file(no_policy.f.root.join("etc/default/ufw")).unwrap();
    let accepting = ready_owl_behind_ufw();
    ufw_rules(&accepting, &[SSH_TUPLE]);
    std::fs::write(
        accepting.f.root.join("etc/default/ufw"),
        "DEFAULT_INPUT_POLICY=\"ACCEPT\"\n",
    )
    .unwrap();
    let disabled = ready_owl_behind_ufw();
    ufw_rules(&disabled, &[SSH_TUPLE]);
    std::fs::write(disabled.f.root.join("etc/ufw/ufw.conf"), "ENABLED=no\n").unwrap();
    let inactive = Radio::new();
    inactive.helper(&backend_helper(Some(owl(serde_json::json!([])))));
    write_exec(&inactive.f.root.join("bin/ufw"), "#!/bin/sh\nexit 0\n");
    ufw_rules(&inactive, &[SSH_TUPLE]);
    for (name, r) in [
        ("the rule is there", rule_there),
        ("the rules can't be read", unreadable),
        ("the default policy can't be read", no_policy),
        ("incoming traffic is accepted by default", accepting),
        ("ufw is disabled", disabled),
        ("ufw.service is inactive", inactive),
    ] {
        assert!(!r.ids().contains(&"firewall".to_string()), "{name}");
    }
}

#[test]
fn a_broader_rule_that_admits_the_receiver_is_enough() {
    for broader in [
        "### tuple ### allow tcp 8771 ::/0 any ::/0 in",
        "### tuple ### allow any any ::/0 any ::/0 in_awdl0",
        "### tuple ### allow tcp 8000:9000 ::/0 any ::/0 in",
        "### tuple ### allow tcp 80,443,8771 ::/0 any ::/0 in",
        "### tuple ### limit tcp 8771 ::/0 any ::/0 in",
        "### tuple ### allow_log tcp 8771 ::/0 any ::/0 in",
    ] {
        let r = ready_owl_behind_ufw();
        ufw_rules(&r, &[SSH_TUPLE, broader]);
        assert!(!r.ids().contains(&"firewall".to_string()), "{broader}");
    }
}

#[test]
fn a_rule_that_cant_admit_the_receiver_doesnt_count() {
    for other in [
        RECEIVER_TUPLE.replace(" 8771 ", " 87710 "),
        RECEIVER_TUPLE.replace(" 8771 ", " 8772:9000 "),
        RECEIVER_TUPLE.replace("in_awdl0", "in_awdl01"),
        RECEIVER_TUPLE.replace("in_awdl0", "out_awdl0"),
        RECEIVER_TUPLE.replace(" tcp ", " udp "),
        RECEIVER_TUPLE.replace("allow", "deny"),
    ] {
        let r = ready_owl_behind_ufw();
        ufw_rules(&r, &[&other]);
        assert!(r.ids().contains(&"firewall".to_string()), "{other}");
    }
}

#[test]
fn install_adds_the_rule_unless_it_is_known_to_be_there() {
    for (rules, adds) in [
        (Some(&[SSH_TUPLE][..]), true),
        (None, true),
        (Some(&[SSH_TUPLE, RECEIVER_TUPLE][..]), false),
    ] {
        let r = ready_owl_behind_ufw();
        if let Some(rules) = rules {
            ufw_rules(&r, rules);
        }
        let out = r.run(&["install-driver"]);
        let stdout = text(&out.stdout);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        assert_eq!(
            stdout.contains(" firewall install"),
            adds,
            "{rules:?}: {stdout}"
        );
    }
}

#[test]
fn a_current_driver_with_the_rule_in_place_has_nothing_to_do() {
    if !receiver_libs_here() {
        eprintln!("this machine lacks the receiver's packages; nothing would be current");
        return;
    }
    for probe in [None, Some(awdl_hooks(serde_json::json!([])))] {
        let r = Radio::new();
        r.helper(&backend_helper(probe.clone()));
        on_a_mac(&r);
        with_driver(&r, Some("0.10.0-1"));
        with_ufw_active(&r);
        ufw_rules(&r, &[SSH_TUPLE, RECEIVER_TUPLE]);
        let out = r.run(&["install-driver"]);
        assert_eq!(
            text(&out.stdout),
            "The driver and the Python library the receiver needs are both installed and current. Nothing to do.\n",
            "{probe:?}"
        );
    }
}

/// The identity commands log what reached them.
fn logging_identity(f: &Fixture) {
    std::fs::write(
        f.root.join("plugins/netmojo.omdrop/bin/identity.py"),
        "import os, sys\nwith open(os.environ['CAPTURE'], 'a') as f:\n    f.write('identity.py ' + ' '.join(sys.argv[1:]) + '\\n')\n",
    )
    .unwrap();
}

#[test]
fn the_1password_identity_follows_the_backends_contract_not_the_driver_package() {
    let r = Radio::new();
    logging_identity(&r.f);
    // No brcmfmac-awdl-dkms is installed (pacman answers nothing).
    r.helper(&backend_helper(Some(owl(serde_json::json!([])))));
    let out = r.run(&["identity", "1password", "import"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let events = std::fs::read_to_string(&r.f.capture).unwrap();
    assert!(events.contains("identity.py import\n"), "{events}");
    // omdrop-awdl's hooks state their package version as the contract.
    r.helper(&backend_helper(Some(awdl_hooks(serde_json::json!([])))));
    let out = r.run(&["identity", "1password", "import"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));

    let mut probe = owl(serde_json::json!([]));
    probe["contract"] = "0.6.9".into();
    r.helper(&backend_helper(Some(probe)));
    let out = r.run(&["identity", "1password", "use", "item"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        text(&out.stderr),
        "Keeping the identity in 1Password needs a radio backend that follows contract 0.7.0 or newer (owl follows 0.6.9).\n"
    );
    let events = std::fs::read_to_string(&r.f.capture).unwrap();
    assert!(!events.contains("identity.py use"), "{events}");
}

#[test]
fn without_a_probe_the_1password_identity_still_needs_the_driver_package() {
    let r = Radio::new();
    logging_identity(&r.f);
    r.helper(&backend_helper(None));
    let out = r.run(&["identity", "1password", "import"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        text(&out.stderr),
        "Keeping the identity in 1Password needs driver 0.7.0 or newer (installed: none). Update it with: omdrop install-driver\n"
    );
}

#[test]
fn the_1password_identity_waits_for_a_backend_that_answers() {
    let mut r = Radio::new();
    r.helper(HUNG);
    r.set("OMDROP_PROBE_TIMEOUT", "1");
    let out = r.run(&["identity", "1password", "import"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("did not answer"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn a_missing_sender_names_the_backend_not_install_driver() {
    let r = Radio::new();
    let mut probe = owl(serde_json::json!([]));
    probe["contract"] = "0.8.1".into();
    r.helper(&backend_helper(Some(probe)));
    let photo = r.f.root.join("photo.jpg");
    std::fs::write(&photo, "x").unwrap();
    let out = r.run(&["send", photo.to_str().unwrap()]);
    assert_ne!(out.status.code(), Some(0));
    assert_eq!(
        text(&out.stderr),
        "The program that sends files is not installed. It comes with the radio backend. Update the package that provides it (owl): omdrop install-driver leaves it alone.\n"
    );

    // omdrop-awdl, with or without its hooks, is what install-driver updates.
    for helper in [None, Some(awdl_hooks(serde_json::json!([])))] {
        r.helper(&backend_helper(helper.clone()));
        let out = r.run(&["send", photo.to_str().unwrap()]);
        assert_eq!(
            text(&out.stderr),
            "The program that sends files is not installed. It comes with the Wi-Fi driver package. Update it with: omdrop install-driver\n",
            "{helper:?}"
        );
    }
}

/// The fixture's plugin, as the omdrop package installs it: under a root that
/// OMDROP_PACKAGE_ROOT names in place of /usr. Omarchy's two plugin commands
/// are stubbed to log their calls.
fn packaged(f: &Fixture) -> (PathBuf, PathBuf) {
    let log = r#"printf '%s\n' "$(basename "$0") $*" >> "$CAPTURE""#;
    for name in ["omarchy-shell", "omarchy-plugin-enable"] {
        // ENABLE_RC makes adding the widget fail.
        write_exec(
            &f.root.join("bin").join(name),
            &format!("#!/bin/sh\n{log}\nexit \"${{ENABLE_RC:-0}}\"\n"),
        );
    }
    let plugin = std::fs::canonicalize(f.root.join("plugins/netmojo.omdrop")).unwrap();
    let target = f.root.join("home/.config/omarchy/plugins/netmojo.omdrop");
    (plugin, target)
}

fn root_env(f: &Fixture) -> String {
    f.root.display().to_string()
}

#[test]
fn setup_links_a_packaged_plugin_into_the_shells_plugins_once() {
    let f = Fixture::new();
    let (plugin, target) = packaged(&f);
    let root = root_env(&f);
    let (out, ev) = f.run(&["setup"], &[("OMDROP_PACKAGE_ROOT", &root)]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(std::fs::read_link(&target).unwrap(), plugin);
    assert!(text(&out.stdout).contains("Added Omdrop to the shell's plugins"));
    assert!(ev.contains("omarchy-shell shell rescanPlugins"), "{ev}");
    assert!(ev.contains("omarchy-plugin-enable netmojo.omdrop"), "{ev}");

    // Already linked: nothing to do, and the widget is not added twice.
    let (out, ev) = f.run(&["setup"], &[("OMDROP_PACKAGE_ROOT", &root)]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(ev.matches("omarchy-plugin-enable").count(), 1, "{ev}");
}

#[test]
fn setup_from_a_checkout_links_nothing() {
    let f = Fixture::new();
    let (_, target) = packaged(&f);
    let (out, _) = f.run(&["setup"], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(!target.exists() && std::fs::symlink_metadata(&target).is_err());
}

#[test]
fn a_previous_installation_is_kept_without_a_terminal() {
    // The panel's first `omdrop on` runs setup with no one to ask.
    let f = Fixture::new();
    let (_, target) = packaged(&f);
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("marker"), "git clone").unwrap();
    let (out, ev) = f.run(&["setup"], &[("OMDROP_PACKAGE_ROOT", &root_env(&f))]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(
        std::fs::read_to_string(target.join("marker")).unwrap(),
        "git clone"
    );
    assert!(
        text(&out.stderr).contains("Run omdrop setup in a terminal to replace it"),
        "{}",
        text(&out.stderr)
    );
    assert!(!ev.contains("omarchy-plugin-enable"), "{ev}");
}

#[test]
fn a_previous_installation_is_replaced_when_the_user_agrees() {
    // script(1) gives setup the terminal its question needs; Enter is Yes.
    let Ok(script) = which_script() else {
        eprintln!("skipped: no script(1)");
        return;
    };
    let f = Fixture::new();
    let (plugin, target) = packaged(&f);
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("marker"), "git clone").unwrap();
    std::fs::write(target.join("manifest.json"), r#"{"version": "0.0.1"}"#).unwrap();
    let mut cmd = f.command_as(
        &script,
        &[
            "-qec",
            &format!("{} setup", f.omdrop.display()),
            "/dev/null",
        ],
    );
    cmd.env("OMDROP_PACKAGE_ROOT", root_env(&f))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    use std::io::Write;
    child.stdin.take().unwrap().write_all(b"\n").unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stdout));
    assert!(
        text(&out.stdout).contains("Previous Omdrop plugin installation detected at",)
            && text(&out.stdout)
                .contains("will replace it with a newer version (0.0.1 → 9.9.9). Continue? (Y/n)"),
        "{}",
        text(&out.stdout)
    );
    assert_eq!(std::fs::read_link(&target).unwrap(), plugin);
    let aside: Vec<_> = std::fs::read_dir(target.parent().unwrap())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with(".netmojo.omdrop.replaced-")
        })
        .collect();
    assert_eq!(aside.len(), 1);
    assert_eq!(
        std::fs::read_to_string(aside[0].path().join("marker")).unwrap(),
        "git clone"
    );
}

fn which_script() -> Result<PathBuf, ()> {
    ["/usr/bin/script", "/bin/script"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
        .ok_or(())
}

#[test]
fn end_of_input_keeps_the_previous_installation() {
    // Ctrl-D at the question is No; only an empty line is Yes.
    let Ok(script) = which_script() else {
        eprintln!("skipped: no script(1)");
        return;
    };
    let f = Fixture::new();
    let (_, target) = packaged(&f);
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("marker"), "git clone").unwrap();
    let mut cmd = f.command_as(
        &script,
        &[
            "-qec",
            &format!("{} setup", f.omdrop.display()),
            "/dev/null",
        ],
    );
    cmd.env("OMDROP_PACKAGE_ROOT", root_env(&f))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    use std::io::Write;
    child.stdin.take().unwrap().write_all(b"\x04").unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stdout));
    assert_eq!(
        std::fs::read_to_string(target.join("marker")).unwrap(),
        "git clone"
    );
}

#[test]
fn a_failed_widget_add_is_retried_until_it_works_and_not_after() {
    let f = Fixture::new();
    packaged(&f);
    let root = root_env(&f);
    let (out, _) = f.run(
        &["setup"],
        &[("OMDROP_PACKAGE_ROOT", &root), ("ENABLE_RC", "1")],
    );
    assert!(
        text(&out.stderr).contains("The next omdrop setup tries again"),
        "{}",
        text(&out.stderr)
    );
    f.run(&["setup"], &[("OMDROP_PACKAGE_ROOT", &root)]);
    let (_, ev) = f.run(&["setup"], &[("OMDROP_PACKAGE_ROOT", &root)]);
    // Once when it failed, once when it worked, and never again: a user who
    // removes the widget keeps it removed.
    assert_eq!(ev.matches("omarchy-plugin-enable").count(), 2, "{ev}");
}

#[test]
fn a_packaged_setup_leaves_the_path_link_alone() {
    // /usr/bin/omdrop is the command; a link to an older copy names the path
    // under ~/.config, which the package's link takes over.
    let f = Fixture::new();
    let (_, target) = packaged(&f);
    let link = f.root.join("home/.local/bin/omdrop");
    std::fs::create_dir_all(link.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(target.join("bin/omdrop"), &link).unwrap();
    let (out, _) = f.run(&["setup"], &[("OMDROP_PACKAGE_ROOT", &root_env(&f))]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(
        std::fs::read_link(&link).unwrap(),
        target.join("bin/omdrop")
    );
}
