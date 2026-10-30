//! omdrop-radio against the mock backend in tests/mock-backend, without root,
//! through the test seam (OMDROP_RADIO_TEST_ROOT; docs/backend-contract.md).
//!
//! Each test gets its own copy of the binary: the supervisor and any start in
//! progress are found by their exact argv (`<exe> __supervise`, `<exe>
//! start`), so separate copies keep parallel tests from seeing each other.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{PoisonError, RwLock};
use std::time::{Duration, Instant};

const HOOKS: [&str; 10] = [
    "probe",
    "up",
    "identity",
    "tick",
    "down",
    "peer-watch",
    "peers",
    "diag",
    "read",
    "trace",
];

struct Fx {
    _dir: tempfile::TempDir,
    root: PathBuf,
    bin: PathBuf,
}

/// Tests copy executables (the binary, the mock hooks) and start processes
/// in parallel. A process forked while another test has a copy open for
/// writing inherits that descriptor until it execs, and running the copy in
/// that moment fails with ETXTBSY ("Text file busy"); under load this failed
/// whichever test it landed on. So copying takes this lock exclusively, and
/// every process start takes it shared, from fork until exec only.
static FORK: RwLock<()> = RwLock::new(());

fn install(src: &Path, dst: &Path) {
    let _only_writer = FORK.write().unwrap_or_else(PoisonError::into_inner);
    fs::copy(src, dst).unwrap();
    fs::set_permissions(dst, fs::Permissions::from_mode(0o755)).unwrap();
}

/// Start `c` while no executable is being written; see [`FORK`].
fn spawn_quietly(c: &mut Command) -> io::Result<Child> {
    let _forking = FORK.read().unwrap_or_else(PoisonError::into_inner);
    c.spawn()
}

/// [`Command::output`], with the fork done under [`FORK`] and the wait not.
fn output_of(c: &mut Command) -> io::Result<Output> {
    c.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    spawn_quietly(c)?.wait_with_output()
}

impl Fx {
    fn new() -> Fx {
        // Planted state must pass the helper's trust check: not writable by
        // group or others.
        // SAFETY: umask only sets this process's file-creation mask.
        unsafe { libc::umask(0o022) };
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let mock = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/mock-backend");
        for d in ["lib", "hooks", "mock", "conf", "proc/sys/kernel", "bin"] {
            fs::create_dir_all(root.join(d)).unwrap();
        }
        for d in ["lib", "hooks"] {
            fs::set_permissions(root.join(d), fs::Permissions::from_mode(0o755)).unwrap();
        }
        let bin = root.join("lib/omdrop-radio");
        install(Path::new(env!("CARGO_BIN_EXE_omdrop-radio")), &bin);
        install(&mock.join("omdrop-adv"), &root.join("lib/omdrop-adv"));
        for h in HOOKS {
            install(&mock.join("hook"), &root.join("hooks").join(h));
        }
        fs::write(root.join("proc/sys/kernel/hostname"), "testhost\n").unwrap();
        Fx {
            _dir: dir,
            root,
            bin,
        }
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(&self.bin);
        c.args(args).env("OMDROP_RADIO_TEST_ROOT", &self.root);
        c
    }

    /// Run to completion. Retries ETXTBSY: a sibling test forking while our
    /// copy of the binary was open for writing can briefly hold it.
    fn run(&self, args: &[&str]) -> Output {
        self.run_with(args, &[])
    }

    fn run_with(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        for _ in 0..50 {
            let mut c = self.command(args);
            c.envs(env.iter().copied());
            match output_of(&mut c) {
                Ok(o) => return o,
                Err(e) if e.raw_os_error() == Some(libc_etxtbsy()) => {
                    std::thread::sleep(Duration::from_millis(20))
                }
                Err(e) => panic!("{e}"),
            }
        }
        panic!("binary stayed busy");
    }

    fn spawn(&self, args: &[&str]) -> Child {
        for _ in 0..50 {
            match spawn_quietly(
                self.command(args)
                    .stdout(Stdio::null())
                    .stderr(Stdio::piped()),
            ) {
                Ok(c) => return c,
                Err(e) if e.raw_os_error() == Some(libc_etxtbsy()) => {
                    std::thread::sleep(Duration::from_millis(20))
                }
                Err(e) => panic!("{e}"),
            }
        }
        panic!("binary stayed busy");
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    fn read(&self, rel: &str) -> String {
        fs::read_to_string(self.path(rel)).unwrap_or_default()
    }

    fn mock(&self, name: &str, content: &str) {
        fs::write(self.path("mock").join(name), content).unwrap();
    }

    /// Pause `hook` (the mock waits while `mock/<hook>.hold` exists) until
    /// the guard drops, so a failing test never leaves a hook paused.
    fn hold(&self, hook: &str) -> Hold {
        let p = self.path("mock").join(format!("{hook}.hold"));
        fs::write(&p, "").unwrap();
        Hold(p)
    }

    fn calls(&self) -> Vec<String> {
        self.read("calls").lines().map(str::to_string).collect()
    }

    fn called(&self, line: &str) -> bool {
        self.calls().iter().any(|c| c == line)
    }

    fn status(&self) -> serde_json::Value {
        let o = self.run(&["status", "--json"]);
        assert_eq!(o.status.code(), Some(0));
        serde_json::from_slice(&o.stdout).unwrap()
    }

    fn supervisors(&self) -> Vec<u32> {
        procs_with(&[self.bin.as_os_str().as_encoded_bytes(), b"__supervise"])
    }
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = output_of(&mut self.command(&["stop"]));
        // Anything still running from this fixture: its argv names our root.
        let root = self.root.as_os_str().as_encoded_bytes().to_vec();
        for pid in all_pids() {
            let argv = fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
            if argv.windows(root.len()).any(|w| w == root.as_slice()) {
                let _ = output_of(Command::new("kill").args(["-KILL", &pid.to_string()]));
            }
        }
    }
}

/// A paused mock hook; see [`Fx::hold`].
struct Hold(PathBuf);

impl Drop for Hold {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn libc_etxtbsy() -> i32 {
    26
}

fn all_pids() -> Vec<u32> {
    fs::read_dir("/proc")
        .unwrap()
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse().ok())
        .collect()
}

fn procs_with(pair: &[&[u8]; 2]) -> Vec<u32> {
    all_pids()
        .into_iter()
        .filter(|pid| {
            let raw = fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
            let argv: Vec<&[u8]> = raw.split(|&b| b == 0).collect();
            argv.windows(2).any(|w| w[0] == pair[0] && w[1] == pair[1])
        })
        .filter(|pid| alive(*pid))
        .collect()
}

fn alive(pid: u32) -> bool {
    fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|s| {
            s.rsplit_once(')')
                .map(|(_, t)| !t.trim_start().starts_with('Z'))
        })
        .unwrap_or(false)
}

fn wait_for(limit: Duration, mut f: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + limit;
    while Instant::now() < end {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    f()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn last_line(s: &str) -> &str {
    s.lines().last().unwrap_or("")
}

/// Recorded children (pid tag start) from the run directory.
fn recorded(fx: &Fx) -> Vec<(u32, String)> {
    fx.read("run/pids")
        .lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            Some((f.next()?.parse().ok()?, f.next()?.to_string()))
        })
        .collect()
}

#[test]
fn a_window_opens_runs_and_stops() {
    let fx = Fx::new();
    let o = fx.run(&["start", "600"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert!(last_line(&stderr(&o)).ends_with("(600s)"), "{}", stderr(&o));
    // Probe first, then up, then the identity, in that order.
    let calls = fx.calls();
    assert_eq!(&calls[..3], ["probe --json", "up ", "identity "]);
    // Hook stderr is relayed, timestamped, into the run log.
    assert!(
        fx.read("run/log")
            .lines()
            .any(|l| l.ends_with(" mock up: bringing awdl0 up") && l.len() > 10)
    );

    let s = fx.status();
    assert_eq!(s["visible"], true);
    assert_eq!(s["reason"], "unproven");
    assert_eq!(s["rx_proven"], false);
    assert_eq!(s["peer_op"], "ok");
    let remaining = s["remaining"].as_u64().unwrap();
    assert!((590..=600).contains(&remaining), "{remaining}");
    assert_eq!(fx.supervisors().len(), 1);

    // The supervisor starts its children after `start` returns; under load
    // the second may not be recorded yet, so wait for both.
    assert!(wait_for(Duration::from_secs(30), || recorded(&fx).len() == 2));
    let kids = recorded(&fx);
    let tags: Vec<&str> = kids.iter().map(|(_, t)| t.as_str()).collect();
    assert_eq!(tags, ["mdns", "peers"]);
    assert!(wait_for(Duration::from_secs(30), || fx.called("tick 1")));
    assert!(wait_for(Duration::from_secs(30), || {
        fx.read("adv-calls")
            .contains("announce --iface awdl0 --count 40 --interval 0.02 --flags 137 --seq 100\n")
    }));
    assert!(
        fx.read("adv-calls")
            .contains("mdns --iface awdl0 --port 8771 --flags 137\n")
    );
    assert!(!fx.path("run/supervisor.token").exists());

    let o = fx.run(&["stop"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let s = fx.status();
    assert_eq!(s["visible"], false);
    assert_eq!(s["reason"], "stopped");
    assert_eq!(s["remaining"], serde_json::Value::Null);
    assert!(fx.supervisors().is_empty());
    for (pid, tag) in kids {
        assert!(
            wait_for(Duration::from_secs(3), || !alive(pid)),
            "{tag} survived stop"
        );
    }
    assert!(fx.called("peer-watch "), "{:?}", fx.calls());
    assert!(fx.called("peer-watch TERM"));
    assert!(fx.called("down stopped"));
    assert!(!fx.path("run/until").exists());
    // Idempotent.
    assert_eq!(fx.run(&["stop"]).status.code(), Some(0));
    assert_eq!(fx.status()["reason"], "stopped");
}

#[test]
fn a_second_start_moves_the_deadline_instead_of_stacking() {
    let fx = Fx::new();
    assert_eq!(fx.run(&["start", "600"]).status.code(), Some(0));
    let o = fx.run(&["start", "0"]);
    assert_eq!(o.status.code(), Some(5), "{}", stderr(&o));
    assert!(stderr(&o).contains("window now runs until turned off"));
    assert_eq!(fx.read("run/until").trim(), "0");
    assert_eq!(fx.status()["remaining"], serde_json::Value::Null);
    let o = fx.run(&["start", "300"]);
    assert_eq!(o.status.code(), Some(5));
    assert!(stderr(&o).contains("window extended to "));
    let r = fx.status()["remaining"].as_u64().unwrap();
    assert!((290..=300).contains(&r), "{r}");
    assert_eq!(fx.supervisors().len(), 1);
    assert_eq!(fx.calls().iter().filter(|c| c.starts_with("up")).count(), 1);
}

fn ups(fx: &Fx) -> usize {
    fx.calls().iter().filter(|c| c.starts_with("up ")).count()
}

/// Greptile P1 on PR #74: a press after the supervisor had decided to end the
/// window, but before it exited, found it alive, rewrote `until` and exited 5
/// ("extended"); the supervisor then closed the window anyway. Here the
/// supervisor is held in `down expired`, in the middle of closing. The press
/// must wait for it to finish and then open a new window.
#[test]
fn a_start_while_the_window_closes_opens_a_new_one() {
    let fx = Fx::new();
    fx.mock("up.stdout", r#"{"announce":{"period_s":1}}"#);
    let down = fx.hold("down");
    assert_eq!(fx.run(&["start", "2"]).status.code(), Some(0));
    assert!(wait_for(Duration::from_secs(30), || fx.called("down expired")));
    let old = fx.supervisors();
    assert_eq!(old.len(), 1, "the closing supervisor is still running");

    let mut again = fx.spawn(&["start", "600"]);
    // Either it waits for the closing supervisor, or (the bug) it answers.
    assert!(wait_for(Duration::from_secs(30), || {
        fx.read("run/log").contains("the window is closing")
            || !matches!(again.try_wait(), Ok(None))
    }));
    drop(down);
    let o = again.wait_with_output().unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert!(
        stderr(&o).contains("the window is closing; opening a new one once it has"),
        "{}",
        stderr(&o)
    );
    assert!(!alive(old[0]), "start opened a window over the closing one");
    let s = fx.status();
    assert_eq!(s["visible"], true, "{s}");
    let r = s["remaining"].as_u64().unwrap();
    assert!((500..=600).contains(&r), "{r}");
    let new = fx.supervisors();
    assert_eq!(new.len(), 1);
    assert_ne!(new, old);
    assert_eq!(ups(&fx), 2);
    // The new window runs: its supervisor ticks on past a full interval.
    let ticks = fx.calls().iter().filter(|c| c.starts_with("tick ")).count();
    assert!(wait_for(Duration::from_secs(30), || {
        fx.calls().iter().filter(|c| c.starts_with("tick ")).count() >= ticks + 2
    }));
    assert_eq!(fx.status()["visible"], true);
    assert_eq!(fx.supervisors(), new);
}

/// The other order: a press after the deadline passed, but before the
/// supervisor has looked at it (here held in `tick`), extends the window,
/// and the supervisor keeps it open.
#[test]
fn a_start_before_the_supervisor_sees_the_deadline_extends_the_window() {
    let fx = Fx::new();
    fx.mock("up.stdout", r#"{"announce":{"period_s":1}}"#);
    let tick = fx.hold("tick");
    assert_eq!(fx.run(&["start", "2"]).status.code(), Some(0));
    assert!(wait_for(Duration::from_secs(30), || fx.called("tick 1")));
    assert!(wait_for(Duration::from_secs(30), || fx.status()["visible"] == false));
    let sups = fx.supervisors();
    assert_eq!(sups.len(), 1);

    let o = fx.run(&["start", "600"]);
    assert_eq!(o.status.code(), Some(5), "{}", stderr(&o));
    assert!(stderr(&o).contains("window extended to "), "{}", stderr(&o));
    drop(tick);
    assert!(wait_for(Duration::from_secs(30), || fx.called("tick 2")));
    assert!(!fx.called("down expired"), "{:?}", fx.calls());
    assert_eq!(fx.supervisors(), sups);
    let s = fx.status();
    assert_eq!(s["visible"], true, "{s}");
    let r = s["remaining"].as_u64().unwrap();
    assert!((500..=600).contains(&r), "{r}");
    assert_eq!(ups(&fx), 1);
}

/// `stop` reaches a start that is waiting for a closing window: it is
/// cancelled, and opens nothing.
#[test]
fn stop_cancels_a_start_waiting_for_the_window_to_close() {
    let fx = Fx::new();
    fx.mock("up.stdout", r#"{"announce":{"period_s":1}}"#);
    let down = fx.hold("down");
    assert_eq!(fx.run(&["start", "2"]).status.code(), Some(0));
    assert!(wait_for(Duration::from_secs(30), || fx.called("down expired")));
    let mut again = fx.spawn(&["start", "600"]);
    assert!(wait_for(Duration::from_secs(30), || fx
        .read("run/log")
        .contains("the window is closing")));

    let mut stop = fx.spawn(&["stop"]);
    assert!(wait_for(Duration::from_secs(30), || !matches!(
        again.try_wait(),
        Ok(None)
    )));
    drop(down);
    let o = again.wait_with_output().unwrap();
    assert_eq!(o.status.code(), Some(3), "{}", stderr(&o));
    assert_eq!(stop.wait().unwrap().code(), Some(0));
    assert_eq!(ups(&fx), 1);
    assert!(fx.supervisors().is_empty());
    assert!(!fx.path("run/until").exists());
    assert_eq!(fx.status()["reason"], "stopped");
}

#[test]
fn a_parked_radio_fails_retryably_and_leaves_nothing_behind() {
    let fx = Fx::new();
    fx.mock("up.rc", "3");
    let o = fx.run(&["start", "600"]);
    assert_eq!(o.status.code(), Some(3));
    // The panel shows the last line: the backend's sentence, after down's log.
    let err = stderr(&o);
    assert!(
        last_line(&err).ends_with("Mock radio: the data path is parked. Try again in a moment."),
        "{err}"
    );
    assert!(err.contains("mock down: start-failed"));
    assert!(fx.called("down start-failed"));
    // status says no_awdl0 here (up never made the interface); the file is
    // what a later window inherits.
    assert_eq!(fx.read("run/reason"), "parked");
    for f in ["until", "supervisor", "supervisor.token", "pids"] {
        assert!(!fx.path("run").join(f).exists(), "{f} left behind");
    }
    assert!(fx.supervisors().is_empty());
}

#[test]
fn no_radio_is_exit_4() {
    let fx = Fx::new();
    fx.mock("up.rc", "4");
    let o = fx.run(&["start", "60"]);
    assert_eq!(o.status.code(), Some(4));
    assert!(last_line(&stderr(&o)).ends_with("Mock radio: no such radio here."));
    let s = fx.status();
    assert_eq!(s["reason"], "no_awdl0");
    assert_eq!(s["visible"], false);
}

#[test]
fn an_up_without_a_link_local_does_not_open_a_window() {
    let fx = Fx::new();
    fx.mock("no-link-local", "");
    let o = fx.run(&["start", "60"]);
    assert_eq!(o.status.code(), Some(4), "{}", stderr(&o));
    assert!(last_line(&stderr(&o)).contains("no link-local"));
    assert!(fx.called("down start-failed"));
    assert!(fx.supervisors().is_empty());
}

#[test]
fn a_window_expires_by_itself_with_the_backends_announce_settings() {
    let fx = Fx::new();
    fx.mock(
        "up.stdout",
        r#"{"announce":{"count":3,"interval_us":1000,"period_s":1,"plain":true},"mdns":false}"#,
    );
    let o = fx.run(&["start", "2"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert!(wait_for(Duration::from_secs(10), || fx.status()["reason"]
        == "expired"));
    assert!(wait_for(Duration::from_secs(5), || fx.called("down expired")));
    assert!(wait_for(Duration::from_secs(5), || fx
        .supervisors()
        .is_empty()));
    let adv = fx.read("adv-calls");
    assert!(
        adv.contains(
            "announce --iface awdl0 --count 3 --interval 0.001 --flags 137 --seq 100 --plain\n"
        ),
        "{adv}"
    );
    assert!(!adv.contains("mdns"), "{adv}");
    assert!(fx.read("run/log").contains("window expired"));
    assert!(fx.called("peer-watch TERM"));
}

#[test]
fn data_frames_prove_receive() {
    let fx = Fx::new();
    fx.mock("up.stdout", r#"{"announce":{"period_s":1}}"#);
    assert_eq!(fx.run(&["start", "0"]).status.code(), Some(0));
    assert_eq!(fx.status()["reason"], "unproven");
    fs::write(fx.path("sys/class/net/awdl0/statistics/rx_packets"), "7\n").unwrap();
    assert!(wait_for(Duration::from_secs(5), || fx.status()["reason"] == "ok"));
    assert_eq!(fx.status()["rx_proven"], true);
    // A backend's failing peer registration makes "ok" untrue for some peers.
    fs::write(fx.path("run/peerop.degraded"), "12:00:00Z aa:bb\n").unwrap();
    let s = fx.status();
    assert_eq!(
        (s["reason"].as_str(), s["peer_op"].as_str()),
        (Some("peer_op_failed"), Some("degraded"))
    );
    let text = fx.run(&["status"]);
    assert_eq!(
        String::from_utf8_lossy(&text.stdout),
        "visible=true remaining=null reason=peer_op_failed rx_proven=true peer_op=degraded\n"
    );
    assert!(stderr(&text).contains("peer_op ADD is failing"));
}

#[test]
fn a_lost_radio_ends_the_window() {
    let fx = Fx::new();
    fx.mock("up.stdout", r#"{"announce":{"period_s":1}}"#);
    assert_eq!(fx.run(&["start", "0"]).status.code(), Some(0));
    fx.mock("tick.rc", "4");
    assert!(wait_for(Duration::from_secs(8), || fx.called("down radio-lost")));
    assert!(wait_for(Duration::from_secs(5), || fx
        .supervisors()
        .is_empty()));
    assert_eq!(fx.read("run/reason"), "no_awdl0");
}

#[test]
fn stop_cancels_a_start_still_bringing_the_radio_up() {
    let fx = Fx::new();
    fx.mock("up.sleep", "30");
    let mut start = fx.spawn(&["start", "600"]);
    assert!(wait_for(Duration::from_secs(5), || fx.called("up ")));
    let t = Instant::now();
    let o = fx.run(&["stop"]);
    assert_eq!(o.status.code(), Some(0));
    assert!(stderr(&o).contains("cancelled a start still in its gate"));
    let code = start.wait().unwrap().code();
    assert_eq!(code, Some(3));
    assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());
    assert!(fx.called("down stopped"));
    assert!(!fx.called("identity "));
    assert!(fx.supervisors().is_empty());
    assert_eq!(fx.read("run/reason"), "stopped");
}

#[test]
fn only_one_start_at_a_time() {
    let fx = Fx::new();
    // Well past the second start's 2 s look for the warm-up, so the first is
    // still in its gate when that look ends.
    fx.mock("up.sleep", "6");
    let mut first = fx.spawn(&["start", "600"]);
    assert!(wait_for(Duration::from_secs(5), || fx.called("up ")));
    let o = fx.run(&["start", "600"]);
    assert_eq!(o.status.code(), Some(5));
    assert!(stderr(&o).contains("another start is already in its gate; not racing it"));
    assert_eq!(first.wait().unwrap().code(), Some(0));
    assert_eq!(fx.supervisors().len(), 1);
}

/// Starts a process called `name` that takes the run directory's start lock,
/// then runs `body` with `$RUN` set, and returns once `until` exists in the
/// run directory. The driver's warm-up is a script called `awdl-warmup` that
/// records its pid in `run/warmup` while it holds the lock.
fn hold_start_lock(fx: &Fx, name: &str, body: &str, until: &str) -> Child {
    let script = fx.path(name);
    fs::write(
        &script,
        format!(
            "#!/usr/bin/env bash\nRUN=\"{run}\"\nexec 9>\"$RUN/start.lock\"\nflock 9\ntouch \"$RUN/locked\"\n{body}\n",
            run = fx.path("run").display()
        ),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    let child = spawn_quietly(&mut Command::new(&script)).unwrap();
    assert!(
        wait_for(Duration::from_secs(5), || fx
            .path(&format!("run/{until}"))
            .exists()),
        "{name} never wrote {until}"
    );
    child
}

#[test]
fn a_start_during_the_boot_warmup_waits_for_it() {
    let fx = Fx::new();
    fs::create_dir_all(fx.path("run")).unwrap();
    let mut warmup = hold_start_lock(
        &fx,
        "awdl-warmup",
        "echo $$ > \"$RUN/warmup\"\nsleep 1.5\nrm -f \"$RUN/warmup\"",
        "warmup",
    );
    let t = Instant::now();
    let o = fx.run(&["start", "600"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert!(stderr(&o).contains("waiting for the boot-time warm-up to finish"));
    assert!(t.elapsed() >= Duration::from_secs(1), "{:?}", t.elapsed());
    warmup.wait().unwrap();
}

/// The warm-up has the lock and has not named itself yet (review 1029, R2).
#[test]
fn a_start_before_the_warmup_names_itself_waits_for_it() {
    let fx = Fx::new();
    fs::create_dir_all(fx.path("run")).unwrap();
    let mut warmup = hold_start_lock(
        &fx,
        "awdl-warmup",
        "sleep 0.5\necho $$ > \"$RUN/warmup\"\nsleep 1\nrm -f \"$RUN/warmup\"",
        "locked",
    );
    assert!(!fx.path("run/warmup").exists());
    let o = fx.run(&["start", "600"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert!(stderr(&o).contains("waiting for the boot-time warm-up to finish"));
    assert!(fx.called("up "));
    warmup.wait().unwrap();
}

/// The warm-up's EXIT trap has removed `warmup` and the lock is not free yet
/// (review 1029, R2).
#[test]
fn a_start_after_the_warmup_unnames_itself_takes_the_lock() {
    let fx = Fx::new();
    fs::create_dir_all(fx.path("run")).unwrap();
    let mut warmup = hold_start_lock(
        &fx,
        "awdl-warmup",
        "rm -f \"$RUN/warmup\"\ntouch \"$RUN/unnamed\"\nsleep 1",
        "unnamed",
    );
    let o = fx.run(&["start", "600"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert!(!stderr(&o).contains("not racing it"));
    assert!(fx.called("up "));
    warmup.wait().unwrap();
}

#[test]
fn a_start_held_by_anything_else_still_refuses() {
    let fx = Fx::new();
    fs::create_dir_all(fx.path("run")).unwrap();
    let mut other = hold_start_lock(
        &fx,
        "other-start",
        "echo $$ > \"$RUN/warmup\"\nsleep 8",
        "warmup",
    );
    let t = Instant::now();
    let o = fx.run(&["start", "600"]);
    assert_eq!(o.status.code(), Some(5), "{}", stderr(&o));
    assert!(stderr(&o).contains("another start is already in its gate; not racing it"));
    assert!(t.elapsed() < Duration::from_secs(4), "{:?}", t.elapsed());
    other.kill().unwrap();
    other.wait().unwrap();
}

/// An ordinary start holds the lock and the warm-up waits for it. The warm-up
/// names itself only once the lock is its own, so a second start still refuses
/// rather than waiting out the first (review 1029).
#[test]
fn a_warmup_queued_behind_another_start_does_not_make_it_wait() {
    let fx = Fx::new();
    fs::create_dir_all(fx.path("run")).unwrap();
    let mut other = hold_start_lock(&fx, "other-start", "sleep 8", "locked");
    let warmup = fx.path("awdl-warmup");
    fs::write(
        &warmup,
        format!(
            "#!/usr/bin/env bash\nexec 9>\"{run}/start.lock\"\nflock 9\necho $$ > \"{run}/warmup\"\n",
            run = fx.path("run").display()
        ),
    )
    .unwrap();
    fs::set_permissions(&warmup, fs::Permissions::from_mode(0o755)).unwrap();
    let mut queued = spawn_quietly(&mut Command::new(&warmup)).unwrap();
    let t = Instant::now();
    let o = fx.run(&["start", "600"]);
    assert_eq!(o.status.code(), Some(5), "{}", stderr(&o));
    assert!(stderr(&o).contains("another start is already in its gate; not racing it"));
    assert!(t.elapsed() < Duration::from_secs(4), "{:?}", t.elapsed());
    for child in [&mut other, &mut queued] {
        child.kill().unwrap();
        child.wait().unwrap();
    }
}

#[test]
fn hooks_and_children_get_only_the_fixed_environment() {
    let fx = Fx::new();
    let o = fx.run_with(
        &["start", "600"],
        &[
            ("FOO", "bar"),
            ("LD_LIBRARY_PATH", "/nonexistent"),
            ("OMDROP_CONF", "/tmp/elsewhere"),
            ("PKEXEC_UID", "1000"),
            ("SUDO_UID", "0123"),
            ("OMDROP_SUPERVISOR_TOKEN", "ab"),
        ],
    );
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    for hook in ["up", "identity"] {
        let env = fx.read(&format!("env.{hook}"));
        let vars: Vec<&str> = env
            .lines()
            .filter_map(|l| l.split_once('=').map(|(k, _)| k))
            .collect();
        assert!(env.contains("PATH=/usr/bin:/usr/sbin\n"), "{env}");
        assert!(env.contains("LANG=C.UTF-8\n"));
        assert!(env.contains("OMDROP_RADIO_HOOKS=1\n"));
        assert!(env.contains(&format!("OMDROP_CONF={}\n", fx.path("conf").display())));
        assert!(env.contains(&format!("OMDROP_RUN_DIR={}\n", fx.path("run").display())));
        assert!(env.contains("PKEXEC_UID=1000\n"));
        for gone in [
            "FOO",
            "LD_LIBRARY_PATH",
            "SUDO_UID",
            "OMDROP_SUPERVISOR_TOKEN",
            "HOME",
        ] {
            assert!(!vars.contains(&gone), "{gone} reached {hook}: {env}");
        }
    }
    assert!(wait_for(Duration::from_secs(5), || fx
        .path("env.tick")
        .exists()));
    assert!(!fx.read("env.tick").contains("OMDROP_SUPERVISOR_TOKEN"));
    assert!(!fx.read("env.peer-watch").contains("FOO="));
}

#[test]
fn invalid_argv_is_refused_before_any_work() {
    let fx = Fx::new();
    let marker = fx.path("executed");
    let payload = format!("a[$(touch {})]", marker.display());
    let nines = "9".repeat(20);
    let cases: Vec<Vec<&str>> = vec![
        vec!["start", "08"],
        vec!["start", "09"],
        vec!["start", "010"],
        vec!["start", &nines],
        vec!["start", "1000000000"],
        vec!["start", &payload],
        vec!["start"],
        vec!["start", "1", "2"],
        vec!["start", "-1"],
        vec!["stop", "now"],
        vec!["status", "--xml"],
        vec!["status", &payload],
        vec!["diag", "601"],
        vec!["diag", "09"],
        vec!["diag", &payload],
        vec!["read"],
        vec!["read", "wsec_key"],
        vec!["read", "pmk"],
        vec!["read", "awdl"],
        vec!["read", &payload],
        vec!["read", "awdl_stats", "09"],
        vec!["read", "awdl_stats", "8193"],
        vec!["read", "awdl_stats", "0"],
        vec!["trace", "maybe"],
        vec!["trace", "on", "off"],
        vec!["peers", "x"],
        vec!["probe"],
        vec!["probe", "--yaml"],
        vec!["bogus"],
        vec![],
        vec!["__supervise", "0", &payload],
    ];
    for args in cases {
        let o = fx.run(&args);
        assert_eq!(o.status.code(), Some(2), "{args:?}: {}", stderr(&o));
        assert!(!marker.exists(), "{args:?} executed its payload");
    }
    assert!(fx.calls().is_empty(), "{:?}", fx.calls());
    assert!(!fx.path("run/start.lock").exists());
    let o = fx.run(&["start", "1000000000"]);
    assert!(stderr(&o).contains("at most 999999999"));
    let o = fx.run(&["read", "wsec_key"]);
    assert!(stderr(&o).contains("limited to awdl_"));
}

#[test]
fn a_direct_supervise_call_is_refused_and_leaves_the_token() {
    let fx = Fx::new();
    fs::create_dir_all(fx.path("run")).unwrap();
    fs::write(fx.path("run/supervisor.token"), "0".repeat(32)).unwrap();
    fs::write(fx.path("run/until"), "0").unwrap();
    for token in [
        None,
        Some("1".repeat(32)),
        Some("0".repeat(31)),
        Some("0".repeat(32) + "\n"),
    ] {
        // run_with, not command().output(): it retries ETXTBSY like every
        // other run here (a sibling test forking while our copy was open).
        let env: Vec<(&str, &str)> = token
            .as_deref()
            .map(|t| vec![("OMDROP_SUPERVISOR_TOKEN", t)])
            .unwrap_or_default();
        let o = fx.run_with(&["__supervise", "0", "0"], &env);
        assert_eq!(o.status.code(), Some(2), "{token:?}");
        assert!(stderr(&o).contains("__supervise is internal"));
    }
    assert_eq!(fx.read("run/supervisor.token"), "0".repeat(32));
    assert!(!fx.path("adv-calls").exists());
    assert!(fx.calls().is_empty());
}

#[test]
fn an_untrusted_hook_is_never_run() {
    let fx = Fx::new();
    fs::set_permissions(fx.path("hooks/up"), fs::Permissions::from_mode(0o775)).unwrap();
    let o = fx.run(&["start", "60"]);
    assert_eq!(o.status.code(), Some(4), "{}", stderr(&o));
    assert!(stderr(&o).contains("writable by group or others"));
    assert!(!fx.called("up "));
    fs::set_permissions(fx.path("hooks/up"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(fx.path("hooks"), fs::Permissions::from_mode(0o777)).unwrap();
    fs::remove_file(fx.path("calls")).unwrap();
    let o = fx.run(&["probe", "--json"]);
    assert_eq!(o.status.code(), Some(4));
    assert!(fx.calls().is_empty());
}

#[test]
fn the_probe_gates_start_and_is_relayed() {
    let fx = Fx::new();
    let o = fx.run(&["probe", "--json"]);
    assert_eq!(o.status.code(), Some(0));
    let p: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(p["backend"], "mock");

    fx.mock(
        "probe.json",
        r#"{"backend":"mock","hooks":2,"hardware":true}"#,
    );
    let o = fx.run(&["start", "60"]);
    assert_eq!(o.status.code(), Some(4));
    assert!(last_line(&stderr(&o)).contains("different version of omdrop's backend contract"));

    fx.mock(
        "probe.json",
        r#"{"backend":"mock","hooks":1,"hardware":false,"missing":[{"id":"hardware","say":"No radio the mock can drive."}]}"#,
    );
    let o = fx.run(&["start", "60"]);
    assert_eq!(o.status.code(), Some(4));
    assert!(last_line(&stderr(&o)).ends_with("No radio the mock can drive."));

    fx.mock("probe.json", "not json");
    assert_eq!(fx.run(&["probe", "--json"]).status.code(), Some(4));
    assert!(!fx.called("up "));

    fs::remove_file(fx.path("hooks/probe")).unwrap();
    let o = fx.run(&["start", "60"]);
    assert_eq!(o.status.code(), Some(4));
    assert!(last_line(&stderr(&o)).contains("radio backend is not installed"));
}

#[test]
fn diagnostics_are_passed_through_with_validated_arguments() {
    let fx = Fx::new();
    let o = fx.run(&["peers"]);
    assert_eq!(o.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&o.stdout).contains("aa:bb:cc:dd:ee:ff  rssi= -50/-52"));
    fx.mock("peers.rc", "4");
    let o = fx.run(&["peers"]);
    assert_eq!(o.status.code(), Some(4));
    assert!(stderr(&o).contains("awdl_advertisers: no reply"));

    assert_eq!(
        String::from_utf8_lossy(&fx.run(&["diag", "0"]).stdout),
        "diag over 0 s\n"
    );
    assert_eq!(fx.run(&["diag"]).status.code(), Some(0));
    let o = fx.run(&["read", "awdl_peer_table"]);
    assert_eq!(
        String::from_utf8_lossy(&o.stdout),
        "awdl_peer_table: 4 bytes\n  00 01 02 03\n"
    );
    assert_eq!(fx.run(&["read", "cap", "64"]).status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&fx.run(&["trace", "on"]).stdout),
        "awdl_trace=1\n"
    );
    assert_eq!(
        String::from_utf8_lossy(&fx.run(&["trace"]).stdout),
        "awdl_trace=1\n"
    );
    assert_eq!(
        String::from_utf8_lossy(&fx.run(&["trace", "off"]).stdout),
        "awdl_trace=0\n"
    );
    let calls = fx.calls();
    for want in [
        "peers ",
        "diag 0",
        "diag 15",
        "read awdl_peer_table 512",
        "read cap 64",
        "trace on",
        "trace status",
        "trace off",
    ] {
        assert!(calls.iter().any(|c| c == want), "{want} not in {calls:?}");
    }
    // Every diagnostic hook's stderr reaches the run log, timestamped.
    let log = fx.read("run/log");
    for line in [
        " awdl_advertisers: no reply (is AWDL enabled?)",
        " mock diag: sampling",
        " mock read: awdl_peer_table",
        " mock trace: on",
    ] {
        assert!(
            log.lines().any(|l| l.ends_with(line)),
            "{line:?} not in {log}"
        );
    }
    // A hook's usage error (a core bug) is exit 2, and anything else 4.
    for (hook, args) in [
        ("peers", &["peers"][..]),
        ("diag", &["diag", "1"]),
        ("read", &["read", "ver"]),
        ("trace", &["trace", "on"]),
    ] {
        fx.mock(&format!("{hook}.rc"), "2");
        assert_eq!(fx.run(args).status.code(), Some(2), "{args:?}");
        fx.mock(&format!("{hook}.rc"), "1");
        assert_eq!(fx.run(args).status.code(), Some(4), "{args:?}");
    }
    for hook in ["read", "trace", "diag", "peers"] {
        fs::remove_file(fx.path("hooks").join(hook)).unwrap();
    }
    for args in [
        &["read", "ver"][..],
        &["trace", "on"],
        &["diag", "1"],
        &["peers"],
    ] {
        assert_eq!(fx.run(args).status.code(), Some(4), "{args:?}");
    }
}

#[test]
fn status_without_a_radio_or_window() {
    let fx = Fx::new();
    let s = fx.status();
    assert_eq!(
        s,
        serde_json::json!({"visible":false,"remaining":null,"reason":"no_awdl0","rx_proven":false,"peer_op":"ok"})
    );
    // Exactly the bytes the panel's and the CLI's pattern matches read.
    let o = fx.run(&["status", "--json"]);
    assert_eq!(
        String::from_utf8_lossy(&o.stdout),
        "{\"visible\":false,\"remaining\":null,\"reason\":\"no_awdl0\",\"rx_proven\":false,\"peer_op\":\"ok\"}\n"
    );
}

// --- run-directory trust, teardown, identity, coexistence ---------------------

fn start_time_of(pid: u32) -> u64 {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let tail = &stat[stat.rfind(')').unwrap() + 2..];
    tail.split_whitespace().nth(19).unwrap().parse().unwrap()
}

/// A process that is none of ours; `leader` makes it its own process group.
fn bystander(leader: bool) -> Child {
    let mut c = Command::new("sleep");
    c.arg("60");
    if leader {
        std::os::unix::process::CommandExt::process_group(&mut c, 0);
    }
    spawn_quietly(&mut c).unwrap()
}

fn mode_of(p: &Path) -> u32 {
    fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
}

#[test]
fn planted_run_dir_state_kills_nothing_and_writes_nowhere_else() {
    let fx = Fx::new();
    let run = fx.path("run");
    fs::create_dir(&run).unwrap();
    fs::set_permissions(&run, fs::Permissions::from_mode(0o777)).unwrap();
    let mut leader = bystander(true);
    let mut member = bystander(false);
    let mut bare = bystander(true);
    // A loose (0666) pids file naming a real group leader by its true start
    // time: untrusted, so never read.
    fs::write(
        run.join("pids"),
        format!("{} peers {}\n", leader.id(), start_time_of(leader.id())),
    )
    .unwrap();
    fs::set_permissions(run.join("pids"), fs::Permissions::from_mode(0o666)).unwrap();
    let outside = fx.path("outside");
    fs::write(&outside, "keep\n").unwrap();
    std::os::unix::fs::symlink(&outside, run.join("log")).unwrap();
    std::os::unix::fs::symlink(&outside, run.join("start.lock")).unwrap();

    let o = fx.run(&["stop"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert!(stderr(&o).contains("was writable by group or others (mode 777); reset to 755"));
    assert_eq!(mode_of(&run), 0o755);
    assert!(!run.join("pids").exists());
    assert!(
        fs::symlink_metadata(run.join("log"))
            .unwrap()
            .file_type()
            .is_file()
    );

    // A trusted pids file whose lines do not prove their process: a bare pid
    // not running a window program, and a start time on a non-leader.
    fs::write(
        run.join("pids"),
        format!(
            "{} mdns\n{} peers {}\n{} ble {}\n",
            bare.id(),
            member.id(),
            start_time_of(member.id()),
            leader.id(),
            start_time_of(leader.id()) + 1
        ),
    )
    .unwrap();
    let o = fx.run(&["start", "60"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert_eq!(fs::read_to_string(&outside).unwrap(), "keep\n");
    assert!(
        fs::symlink_metadata(run.join("start.lock"))
            .unwrap()
            .file_type()
            .is_file()
    );
    for (name, c) in [
        ("leader", &mut leader),
        ("member", &mut member),
        ("bare", &mut bare),
    ] {
        assert!(matches!(c.try_wait(), Ok(None)), "{name} was killed");
    }
    assert_eq!(fx.run(&["stop"]).status.code(), Some(0));
    for c in [&mut leader, &mut member, &mut bare] {
        assert!(matches!(c.try_wait(), Ok(None)));
        let _ = c.kill();
        let _ = c.wait();
    }
}

#[test]
fn a_symlinked_run_dir_is_refused() {
    let fx = Fx::new();
    fs::create_dir(fx.path("elsewhere")).unwrap();
    std::os::unix::fs::symlink(fx.path("elsewhere"), fx.path("run")).unwrap();
    let o = fx.run(&["start", "60"]);
    assert_eq!(o.status.code(), Some(3));
    assert!(
        stderr(&o).contains("refusing the run directory"),
        "{}",
        stderr(&o)
    );
    assert!(fx.calls().is_empty());
    assert_eq!(fs::read_dir(fx.path("elsewhere")).unwrap().count(), 0);
    assert_eq!(fx.run(&["stop"]).status.code(), Some(3));
    assert_eq!(fx.status()["reason"], "no_awdl0");
}

#[test]
fn stop_kills_the_hook_a_killed_supervisor_was_running() {
    let fx = Fx::new();
    fx.mock("up.stdout", r#"{"announce":{"period_s":1}}"#);
    assert_eq!(fx.run(&["start", "0"]).status.code(), Some(0));
    // Tick 1 must have finished before ticks start hanging, or under load
    // tick 1 itself sleeps 60 s and tick 2 never comes. The mock logs a call
    // before reading its sleep, so wait for the announcer burst that follows
    // tick 1 (--seq 100), not for the "tick 1" line.
    assert!(wait_for(Duration::from_secs(30), || fs::read_to_string(
        fx.path("adv-calls")
    )
    .is_ok_and(|s| s.contains("--seq 100"))));
    fx.mock("tick.sleep", "60");
    assert!(wait_for(Duration::from_secs(30), || fx
        .calls()
        .iter()
        .any(|c| c.starts_with("tick ") && c != "tick 1")));
    assert!(wait_for(Duration::from_secs(30), || fx
        .path("run/hook.pgid")
        .exists()));
    let pgid: u32 = fx
        .read("run/hook.pgid")
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert!(alive(pgid));
    let sups = fx.supervisors();
    assert_eq!(sups.len(), 1);
    output_of(Command::new("kill").args(["-KILL", &sups[0].to_string()])).unwrap();
    assert!(wait_for(Duration::from_secs(5), || fx
        .supervisors()
        .is_empty()));
    assert!(
        alive(pgid),
        "the hook died with its supervisor; nothing to test"
    );

    let o = fx.run(&["stop"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert!(stderr(&o).contains(&format!(
        "stopped an orphaned radio hook (process group {pgid})"
    )));
    assert!(wait_for(Duration::from_secs(5), || !alive(pgid)));
    assert!(!fx.path("run/hook.pgid").exists());
}

#[test]
fn a_reused_supervisor_pid_is_not_a_window() {
    let fx = Fx::new();
    assert_eq!(fx.run(&["start", "0"]).status.code(), Some(0));
    let pid = fx.supervisors()[0];
    fs::write(
        fx.path("run/supervisor"),
        format!("{pid} {}\n", start_time_of(pid) + 1),
    )
    .unwrap();
    assert_eq!(fx.status()["visible"], false);
    fs::write(fx.path("run/supervisor"), format!("{pid}\n")).unwrap();
    assert_eq!(fx.status()["visible"], false);
    fs::write(
        fx.path("run/supervisor"),
        format!("{pid} {}\n", start_time_of(pid)),
    )
    .unwrap();
    assert_eq!(fx.status()["visible"], true);
}

/// `bash <legacy script> __supervise 0 0`, as /proc shows a 0.9.x supervisor.
/// The script loops on `sleep 1`, so a killed bash leaves nothing for long,
/// and its output goes nowhere near the test's pipes.
fn legacy_supervisor(fx: &Fx, argv: &[&str]) -> Child {
    let legacy = fx.path("legacy/omdrop-discoverable");
    fs::create_dir_all(legacy.parent().unwrap()).unwrap();
    fs::write(&legacy, "while :; do sleep 1; done\n").unwrap();
    let c = spawn_quietly(
        Command::new("bash")
            .args(argv)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    )
    .unwrap();
    let want: Vec<u8> = std::iter::once("bash")
        .chain(argv.iter().copied())
        .flat_map(|a| a.bytes().chain([0]))
        .collect();
    assert!(wait_for(Duration::from_secs(5), || {
        fs::read(format!("/proc/{}/cmdline", c.id())).unwrap_or_default() == want
    }));
    c
}

fn fake_awdl0(fx: &Fx) {
    let net = fx.path("sys/class/net/awdl0/statistics");
    fs::create_dir_all(&net).unwrap();
    fs::write(net.join("rx_packets"), "0\n").unwrap();
    fs::create_dir_all(fx.path("proc/net")).unwrap();
    fs::write(
        fx.path("proc/net/if_inet6"),
        "fe800000000000000000000000000001 0b 40 20 80 awdl0\n",
    )
    .unwrap();
}

#[test]
fn a_legacy_window_is_reported_kept_and_stoppable() {
    let fx = Fx::new();
    let legacy = fx.path("legacy/omdrop-discoverable");
    let legacy = legacy.to_str().unwrap();
    let mut sup = legacy_supervisor(&fx, &[legacy, "__supervise", "0", "0"]);
    fake_awdl0(&fx);
    fs::create_dir_all(fx.path("run")).unwrap();
    fs::write(fx.path("run/until"), "0").unwrap();
    // Not recorded in `supervisor`: not 0.9.x's window, whatever its argv.
    assert_eq!(fx.status()["visible"], false);
    fs::write(fx.path("run/supervisor"), format!("{}\n", sup.id())).unwrap();
    assert_eq!(fx.status()["visible"], true);

    let o = fx.run(&["start", "60"]);
    assert_eq!(o.status.code(), Some(5), "{}", stderr(&o));
    assert!(stderr(&o).contains("older omdrop-discoverable helper"));
    assert!(fx.calls().is_empty(), "{:?}", fx.calls());
    assert!(matches!(sup.try_wait(), Ok(None)));

    assert_eq!(fx.run(&["stop"]).status.code(), Some(0));
    assert!(wait_for(Duration::from_secs(5), || !matches!(
        sup.try_wait(),
        Ok(None)
    )));
    assert_eq!(fx.status()["visible"], false);
}

#[test]
fn a_supervisor_pair_later_in_argv_is_not_a_window() {
    let fx = Fx::new();
    let legacy = fx.path("legacy/omdrop-discoverable");
    let legacy = legacy.to_str().unwrap();
    let ours = fx.bin.to_str().unwrap();
    // What `pkexec omdrop-discoverable diag 600 <exe> __supervise` makes.
    let mut decoy = legacy_supervisor(
        &fx,
        &[legacy, "diag", legacy, "__supervise", ours, "__supervise"],
    );
    fake_awdl0(&fx);
    fs::create_dir_all(fx.path("run")).unwrap();
    fs::write(fx.path("run/until"), "0").unwrap();
    fs::write(fx.path("run/supervisor"), format!("{}\n", decoy.id())).unwrap();
    assert_eq!(fx.status()["visible"], false);
    fs::write(
        fx.path("run/supervisor"),
        format!("{} {}\n", decoy.id(), start_time_of(decoy.id())),
    )
    .unwrap();
    assert_eq!(fx.status()["visible"], false);
    // start neither refuses nor stops it, and stop leaves it alone.
    let o = fx.run(&["start", "60"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert_eq!(fx.run(&["stop"]).status.code(), Some(0));
    assert!(matches!(decoy.try_wait(), Ok(None)));
    let _ = decoy.kill();
    let _ = decoy.wait();
}

#[test]
fn planted_directories_under_core_names_do_not_wedge_start() {
    let fx = Fx::new();
    let run = fx.path("run");
    fs::create_dir(&run).unwrap();
    fs::set_permissions(&run, fs::Permissions::from_mode(0o777)).unwrap();
    for name in ["start.lock", "log", "until"] {
        fs::create_dir_all(run.join(name).join("deeper")).unwrap();
        fs::write(run.join(name).join("deeper/file"), "x").unwrap();
    }
    let outside = fx.path("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("keep"), "keep").unwrap();
    std::os::unix::fs::symlink(&outside, run.join("start.lock/escape")).unwrap();
    // Present only as a flag: a loose one must not count.
    fs::write(run.join("peerop.degraded"), "x").unwrap();
    fs::set_permissions(
        run.join("peerop.degraded"),
        fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    // A second link to a file elsewhere is not a trusted state file.
    fs::write(fx.path("linked"), "a[$(x)]").unwrap();
    fs::hard_link(fx.path("linked"), run.join("reason")).unwrap();

    let o = fx.run(&["start", "60"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert!(stderr(&o).contains("removed"), "{}", stderr(&o));
    for name in ["start.lock", "log", "until"] {
        assert!(
            fs::symlink_metadata(run.join(name)).unwrap().is_file(),
            "{name}"
        );
    }
    assert!(!run.join("peerop.degraded").exists());
    assert_eq!(fs::read_to_string(outside.join("keep")).unwrap(), "keep");
    assert_eq!(fs::read_to_string(fx.path("linked")).unwrap(), "a[$(x)]");
    let leftovers: Vec<_> = fs::read_dir(&run)
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with(".untrusted"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
    let s = fx.status();
    assert_eq!(
        (s["visible"].as_bool(), s["peer_op"].as_str()),
        (Some(true), Some("ok"))
    );

    // A hard-linked flag planted later reads as absent too.
    fs::write(fx.path("flag"), "").unwrap();
    fs::hard_link(fx.path("flag"), run.join("peerop.degraded")).unwrap();
    assert_eq!(fx.status()["peer_op"], "ok");
}

#[test]
fn stop_during_identity_leaves_no_window_state() {
    let fx = Fx::new();
    fx.mock("identity.sleep", "30");
    let mut start = fx.spawn(&["start", "600"]);
    assert!(wait_for(Duration::from_secs(5), || fx.called("identity ")));
    assert_eq!(fx.run(&["stop"]).status.code(), Some(0));
    assert_eq!(start.wait().unwrap().code(), Some(3));
    assert!(!fx.path("run/until").exists());
    assert!(!fx.path("run/supervisor.token").exists());
    assert_eq!(fx.read("run/reason"), "stopped");
    assert!(fx.supervisors().is_empty());
}
