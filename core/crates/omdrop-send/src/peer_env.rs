//! send-to-peer's real surroundings: the radio helper through pkexec, the
//! BLE wake advertiser, TCP knocks on awdl0, in-process /Discover name
//! lookups, and the `airdrop-send` program.
//!
//! Programs are found the omdrop-core way: `OMDROP_DISCOVERABLE` names the
//! radio helper outright; otherwise a Rust sibling in the directory of this
//! executable (`omdrop-radio`, `omdrop-adv`, `airdrop-send`), falling back to
//! the legacy program in `/usr/lib/omdrop/`. `omdrop-radio` counts only when
//! a radio backend's hooks are installed. `OMDROP_IMPLEMENTATION=python`
//! prefers the legacy programs; `rust`, or unset, prefers these.

use std::fs::File;
use std::io::{self, Read};
use std::net::{Ipv6Addr, SocketAddr, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use crate::airdrop_send::resolve_identity;
use crate::client::{Client, Sender};
use crate::error::PyErr;
use crate::http::Endpoint;
use crate::log::{Logger, Sink};
use crate::send_to_peer::{
    Env, IFACE, WAKE_READY, knock, link_local, lookup_budget, merge_peers, parse_neigh,
    parse_peer_table,
};

const LEGACY_DIR: &str = "/usr/lib/omdrop";
/// Where a radio backend installs the hooks `omdrop-radio` delegates to.
/// A constant, not a setting: whether hooks exist is a fact about the
/// installed system, not something the caller's environment may claim.
const RADIO_HOOKS_DIR: &str = "/usr/lib/omdrop/radio";

/// The running wake advertiser, where the signal handler can reach it.
static WAKE: Mutex<Option<Child>> = Mutex::new(None);
/// The running sender's pid, likewise (0: none).
static SENDER_PID: AtomicU32 = AtomicU32::new(0);

/// The child slot. A panic elsewhere must not stop us from stopping the
/// advert, so a poisoned lock is simply taken over.
fn wake_slot() -> MutexGuard<'static, Option<Child>> {
    WAKE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `OMDROP_IMPLEMENTATION`: `python` prefers the legacy programs, `rust` or
/// unset prefers ours. Anything else is refused, so a typo cannot quietly
/// pick a stack.
pub fn prefer_legacy_checked() -> Result<bool, String> {
    match std::env::var("OMDROP_IMPLEMENTATION").as_deref() {
        Ok("python") => Ok(true),
        Ok("rust") | Ok("") | Err(_) => Ok(false),
        Ok(other) => Err(format!(
            "OMDROP_IMPLEMENTATION must be python or rust, not {other:?}"
        )),
    }
}

fn prefer_legacy() -> bool {
    prefer_legacy_checked().unwrap_or(false)
}

/// The directory of this executable, symlinks resolved.
fn own_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()?
        .parent()
        .map(Path::to_path_buf)
}

/// A Rust sibling and a legacy program, in preference order; the first that
/// exists, else the first.
fn choose(rust: Option<PathBuf>, legacy: PathBuf) -> (PathBuf, bool) {
    let mut order: Vec<(PathBuf, bool)> = Vec::new();
    if prefer_legacy() {
        order.push((legacy.clone(), true));
        order.extend(rust.map(|r| (r, false)));
    } else {
        order.extend(rust.map(|r| (r, false)));
        order.push((legacy.clone(), true));
    }
    order
        .iter()
        .find(|(p, _)| p.exists())
        .cloned()
        .unwrap_or_else(|| order.first().cloned().unwrap_or((legacy, true)))
}

/// The root helper `peers` runs through pkexec: `OMDROP_DISCOVERABLE` if
/// set; else `omdrop-radio` beside this executable, but only when a backend's
/// hooks are installed (without them it cannot read a peer table); else the
/// legacy `omdrop-discoverable`. The same rule as `omdrop`'s.
pub fn helper_path() -> PathBuf {
    if let Some(v) = std::env::var_os("OMDROP_DISCOVERABLE").filter(|v| !v.is_empty()) {
        return PathBuf::from(v);
    }
    let hooks = Path::new(RADIO_HOOKS_DIR).is_dir();
    choose(
        own_dir().filter(|_| hooks).map(|d| d.join("omdrop-radio")),
        Path::new(LEGACY_DIR).join("omdrop-discoverable"),
    )
    .0
}

/// The wake advertiser's argv for `seconds`, or `None` when none is installed.
pub fn advertiser_command(seconds: f64) -> Option<Vec<String>> {
    let (path, legacy) = choose(
        own_dir().map(|d| d.join("omdrop-adv")),
        Path::new(LEGACY_DIR).join("ble-airdrop-adv.py"),
    );
    if !path.exists() {
        return None;
    }
    let secs = (seconds.trunc() as i64).max(1).to_string();
    let path = path.to_string_lossy().into_owned();
    let mut cmd = if legacy {
        vec!["python3".to_owned(), path]
    } else {
        vec![path, "ble".to_owned()]
    };
    cmd.extend(["--arm", "A", "--seconds", &secs, "--interval-ms", "100"].map(str::to_owned));
    Some(cmd)
}

/// The sender's argv prefix.
pub fn sender_command() -> Vec<String> {
    let (path, legacy) = choose(
        own_dir().map(|d| d.join("airdrop-send")),
        Path::new(LEGACY_DIR).join("airdrop-send.py"),
    );
    let path = path.to_string_lossy().into_owned();
    if legacy {
        vec!["python3".to_owned(), path]
    } else {
        vec![path]
    }
}

/// A command whose child starts with no blocked signals. This process
/// blocks SIGINT/SIGTERM/SIGHUP for its signal thread, and a child would
/// otherwise inherit that mask: the advertiser then ignored the SIGTERM that
/// is meant to take the advert down.
fn command(prog: impl AsRef<std::ffi::OsStr>) -> Command {
    use std::os::unix::process::CommandExt;
    let mut cmd = Command::new(prog);
    // SAFETY: the closure runs between fork and exec and calls only
    // sigemptyset and pthread_sigmask, which are async-signal-safe and touch
    // only the stack-local set.
    unsafe {
        cmd.pre_exec(|| {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::pthread_sigmask(libc::SIG_SETMASK, &set, std::ptr::null_mut());
            Ok(())
        });
    }
    cmd
}

/// Is this a local session polkit will treat as active? Only a seated
/// session gets allow_active; a remote or seatless one falls to allow_any,
/// which the action sets to auth_admin.
fn on_a_seat() -> bool {
    let id = std::env::var("XDG_SESSION_ID").unwrap_or_default();
    if let Ok(run) = command("loginctl")
        .args(["show-session", &id, "-p", "Seat"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    {
        let text = String::from_utf8_lossy(&run.stdout);
        if run.status.success() && text.contains("Seat=") {
            return text.trim() != "Seat=";
        }
    }
    // No session to ask about: assume seatless and offer the sudo hint,
    // which is wrong only in the harmless direction.
    std::env::var_os("XDG_SEAT").is_some_and(|v| !v.is_empty())
}

fn exit_code(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .unwrap_or_else(|| -status.signal().unwrap_or(0))
}

/// Stop the wake advert and reap it, so BlueZ drops the advertisement now:
/// SIGTERM, five seconds, then SIGKILL.
pub fn stop_wake_child() {
    let child = wake_slot().take();
    if let Some(mut child) = child {
        terminate(&mut child);
    }
}

fn terminate(child: &mut Child) {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return;
    }
    let pid = libc::pid_t::try_from(child.id()).unwrap_or(0);
    if pid > 0 {
        // SAFETY: kill(2) on our own child's pid; it is unreaped, so the pid
        // cannot have been reused.
        unsafe { libc::kill(pid, libc::SIGTERM) };
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if !matches!(child.try_wait(), Ok(None)) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// Terminate the running sender, if any (on a signal).
pub fn stop_sender_child() {
    let pid = SENDER_PID.load(Ordering::SeqCst);
    if let Ok(pid) = libc::pid_t::try_from(pid)
        && pid > 0
    {
        // SAFETY: kill(2) on our own child's pid. The pid is cleared the
        // moment wait returns, so it names an unreaped child (or, in that
        // instant, a zombie the kernel has not yet released).
        unsafe { libc::kill(pid, libc::SIGTERM) };
    }
}

/// A pipe for the advertiser's stdout and stderr together.
fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` is a valid two-element array for pipe2 to fill.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pipe2 succeeded, so both descriptors are open and owned by us alone.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Wait up to `timeout` for `fd` to be readable.
fn readable(fd: &File, timeout: Duration) -> bool {
    let mut pfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let ms = libc::c_int::try_from(timeout.as_millis()).unwrap_or(libc::c_int::MAX);
    // SAFETY: one valid pollfd for the call's duration.
    unsafe { libc::poll(&mut pfd, 1, ms) > 0 }
}

/// Start the advert and wait for BlueZ to accept it, or explain why not.
///
/// The advertiser prints `START ...` once LEAdvertisingManager1 has taken the
/// advertisement and `REGISTER FAILED` when it has not, so registration is
/// observed rather than assumed: a live pid proves only that the program
/// started. Output is read in chunks and every complete line in hand is
/// examined before waiting on the pipe again, because the advertiser prints
/// its hash-source line and START in one flush; a reader that consumed both
/// and then waited would time out five seconds after the advert was up.
fn wake_start(seconds: f64) -> (bool, Option<String>) {
    let Some(argv) = advertiser_command(seconds) else {
        return (false, None);
    };
    let Some((prog, rest)) = argv.split_first() else {
        return (false, None);
    };
    let spawned = pipe().and_then(|(r, w)| {
        let w2 = w.try_clone()?;
        let child = command(prog)
            .args(rest)
            .stdin(Stdio::null())
            .stdout(Stdio::from(w))
            .stderr(Stdio::from(w2))
            .spawn()?;
        Ok((child, File::from(r)))
    });
    let (child, mut reader) = match spawned {
        Ok(v) => v,
        Err(e) => {
            let text = e.to_string();
            return (
                false,
                Some(format!(
                    "wake not started: {}",
                    text.split(" (os error").next().unwrap_or(&text)
                )),
            );
        }
    };
    *wake_slot() = Some(child);
    let deadline = Instant::now() + Duration::from_secs_f64(WAKE_READY);
    let mut buf: Vec<u8> = Vec::new();
    let mut last = String::new();
    let mut eof = false;
    loop {
        while let Some(i) = buf.iter().position(|&b| b == b'\n') {
            let raw: Vec<u8> = buf.drain(..=i).collect();
            let line = String::from_utf8_lossy(raw.get(..i).unwrap_or_default())
                .trim()
                .to_owned();
            if line.is_empty() {
                continue;
            }
            last = line;
            if last.contains(" START ") {
                // Registration is the start of the window: the peers are
                // polled from here. Keep draining so a chatty advertiser can
                // never block on a full pipe.
                drain(reader);
                return (true, None);
            }
            if last.contains("FAILED") {
                drain(reader);
                return (true, Some(format!("wake not advertising: {last}")));
            }
        }
        let exited = wake_slot()
            .as_mut()
            .is_none_or(|c| !matches!(c.try_wait(), Ok(None)));
        if eof || exited {
            // Drain first: the reason it died is the last thing it said.
            if !eof {
                let mut rest = Vec::new();
                if readable(&reader, Duration::from_millis(200)) {
                    let _ = (&mut reader).take(64 << 10).read_to_end(&mut rest);
                }
                buf.extend_from_slice(&rest);
                buf.push(b'\n');
                eof = true;
                continue;
            }
            stop_wake_child();
            let said = if last.is_empty() {
                "no output".to_owned()
            } else {
                last
            };
            return (false, Some(format!("wake exited: {said}")));
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            drain(reader);
            return (
                true,
                Some(format!("wake did not register within {WAKE_READY:.0}s")),
            );
        }
        if readable(&reader, left.min(Duration::from_millis(250))) {
            let mut chunk = [0u8; 4096];
            match reader.read(&mut chunk) {
                Ok(0) | Err(_) => eof = true,
                Ok(n) => buf.extend_from_slice(chunk.get(..n).unwrap_or_default()),
            }
        }
    }
}

fn drain(mut reader: File) {
    std::thread::spawn(move || {
        let _ = io::copy(&mut reader, &mut io::sink());
    });
}

/// The real environment.
pub struct RealEnv {
    t0: Instant,
    /// The lookup identity, resolved once on first use.
    lookup: OnceLock<Result<Arc<Sender>, String>>,
}

impl Default for RealEnv {
    fn default() -> Self {
        RealEnv {
            t0: Instant::now(),
            lookup: OnceLock::new(),
        }
    }
}

impl RealEnv {
    fn lookup_sender(&self, sender_name: &str) -> Result<Arc<Sender>, String> {
        self.lookup
            .get_or_init(|| {
                let identity = resolve_identity(None, sender_name)
                    .map_err(|e| format!("identity error: {e}"))?;
                let tls = omdrop_proto::tls::client_config(&identity)
                    .map_err(|e| format!("identity error: {e}"))?;
                let sender = Sender {
                    tls,
                    record: identity.record.clone(),
                    computer_name: sender_name.to_owned(),
                    computer_model: "MacBookPro18,3".to_owned(),
                    service_id: String::new(),
                    iface: IFACE.to_owned(),
                    verbose: false,
                    auth_tag: None,
                    should_convert: false,
                    op_timeout: None,
                    bound_upload: false,
                };
                // Said once, not per peer: every lookup would fail the same way.
                Ok(Arc::new(sender))
            })
            .clone()
    }
}

/// One /Discover against `target`, bounded per operation by `timeout` and in
/// total by `timeout + 4` s (the bound the Python version put on each sender
/// subprocess).
fn discover_once(
    base: &Sender,
    target: Ipv6Addr,
    port: u16,
    timeout: f64,
) -> Result<Option<String>, (Option<i32>, String)> {
    let started = Instant::now();
    let op = Duration::try_from_secs_f64(timeout).ok();
    let deadline =
        started + Duration::try_from_secs_f64(timeout + 4.0).unwrap_or(Duration::from_secs(12));
    let sender = Sender {
        op_timeout: op,
        record: base.record.clone(),
        tls: base.tls.clone(),
        computer_name: base.computer_name.clone(),
        computer_model: base.computer_model.clone(),
        service_id: base.service_id.clone(),
        iface: base.iface.clone(),
        verbose: base.verbose,
        auth_tag: None,
        should_convert: false,
        bound_upload: false,
    };
    let log = Logger::new(Sink::Silent);
    let shown = format!("[{target}%{IFACE}]:{port}");
    let endpoint = Endpoint::v6(target, port, Some(IFACE)).map_err(|e| {
        (
            Some(2),
            format!("{shown}: no answer ({})", PyErr::from_io(&e).class),
        )
    })?;
    let mut client = Client::new(&sender, endpoint, &log).with_deadline(deadline);
    client.discover().map_err(|e| {
        if Instant::now() >= deadline {
            (None, "subprocess timeout".to_owned())
        } else {
            (
                Some(2),
                format!("{shown}: no answer ({})", PyErr::from_io(&e).class),
            )
        }
    })
}

/// One line per attempt when `OMDROP_NAME_LOG` names a file. Off unless
/// asked for, and it changes no decision: the receiver operator needs
/// per-attempt UTC bounds, return codes and stderr to line our failures up
/// against their accepts, TLS errors and DISCOVER events.
fn trace(
    mac: &str,
    attempt: u32,
    knocked: bool,
    t0: std::time::SystemTime,
    rc: Option<i32>,
    err: Option<&str>,
) {
    let Some(path) = std::env::var_os("OMDROP_NAME_LOG").filter(|p| !p.is_empty()) else {
        return;
    };
    let rc = rc.map_or_else(|| "None".to_owned(), |c| c.to_string());
    let err = match err {
        Some(e) => crate::pyfmt::list_repr(&[e]),
        None => "[]".to_owned(),
    };
    let line = format!(
        "{}..{} mac={mac} attempt={attempt} knocked={} rc={rc} err={err}\n",
        utc(t0),
        utc(std::time::SystemTime::now()),
        u8::from(knocked)
    );
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
    {
        let _ = io::Write::write_all(&mut f, line.as_bytes());
    }
}

/// `2026-09-21T19:03:18.644Z`. (The Python trace meant milliseconds too, but
/// its format string lost them: `%f` was cut off and `time.strftime` has none.)
fn utc(t: std::time::SystemTime) -> String {
    let d = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let secs = libc::time_t::try_from(d.as_secs()).unwrap_or(0);
    // SAFETY: `tm` is plain old data that gmtime_r fills; both pointers are
    // valid for the call.
    let tm = unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::gmtime_r(&secs, &mut tm).is_null() {
            return format!("{secs}Z");
        }
        tm
    };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        d.subsec_millis()
    )
}

impl Env for RealEnv {
    fn monotonic(&self) -> f64 {
        self.t0.elapsed().as_secs_f64()
    }

    fn sleep(&self, secs: f64) {
        if let Ok(d) = Duration::try_from_secs_f64(secs) {
            std::thread::sleep(d);
        }
    }

    /// Every MAC the firmware can currently hear, strongest signal first.
    ///
    /// Two failures look identical in the output and are not: a room with
    /// nobody in it, and a helper that never ran. Reporting the second as
    /// the first sent a debugging session after the radio when the real
    /// answer was polkit (2026-09-18). polkit grants this without a password
    /// only to a session on a seat; over SSH pkexec fails with "No session
    /// for cookie" before the password is even checked, and `sudo` works.
    fn peers(&self) -> Result<Vec<(String, Option<i64>)>, String> {
        let helper = helper_path();
        let shown = helper.display().to_string();
        let run = command("pkexec")
            .arg(&helper)
            .arg("peers")
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("could not read the peer table (pkexec: {e})"))?;
        if !run.status.success() {
            let stderr = String::from_utf8_lossy(&run.stderr);
            let stdout = String::from_utf8_lossy(&run.stdout);
            let detail = if stderr.trim().is_empty() {
                stdout
            } else {
                stderr
            };
            let last = detail.trim().lines().last().map(str::to_owned);
            let mut msg = format!(
                "could not read the peer table ({shown} exited {})",
                exit_code(run.status)
            );
            if let Some(last) = last {
                msg.push_str(&format!(": {last}"));
            }
            if !on_a_seat() {
                msg.push_str(&format!("\nThis session has no seat, so polkit will not authorize it. Use:\n  sudo {shown} peers"));
            }
            return Err(msg);
        }
        let found = parse_peer_table(&String::from_utf8_lossy(&run.stdout));
        // nud permanent, because that is what the peer watcher writes;
        // without it, FAILED entries from our own unanswered probes would
        // list as peers that were never there.
        let registered = command("ip")
            .args(["-6", "neigh", "show", "dev", IFACE, "nud", "permanent"])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map(|o| parse_neigh(&String::from_utf8_lossy(&o.stdout)))
            .unwrap_or_default();
        let own = std::fs::read_to_string(format!("/sys/class/net/{IFACE}/address"))
            .ok()
            .map(|s| s.trim().to_lowercase());
        Ok(merge_peers(found, registered, own.as_deref()))
    }

    /// A refusal is an answer, not a failure: the peer's stack replied, so
    /// the radio path is fine and only the service is absent.
    fn listening(&self, host: Ipv6Addr, port: u16, timeout: f64) -> bool {
        let Ok(addr) = omdrop_proto::net::scoped(host, port, IFACE) else {
            return false;
        };
        let Ok(t) = Duration::try_from_secs_f64(timeout) else {
            return false;
        };
        if t.is_zero() {
            return false;
        }
        TcpStream::connect_timeout(&SocketAddr::V6(addr), t).is_ok()
    }

    fn wake_start(&self, seconds: f64) -> (bool, Option<String>) {
        wake_start(seconds)
    }

    fn wake_stop(&self) {
        stop_wake_child();
    }

    /// Ask one peer what it calls itself, after a cheap TCP knock: a
    /// /Discover costs TLS and attempts, and for a device that is not
    /// receiving all of that is spent to learn what one refused connection
    /// says in a moment (six peers took 49 s before the knock, under 2 s
    /// after). A peer just woken gets knocks until the wake's deadline: in the
    /// run that worked (2026-09-21 19:03) the port did not answer until 14.8 s
    /// after the advert went up, on a listener bound within a millisecond of
    /// recognition.
    fn peer_name(
        &self,
        mac: &str,
        port: u16,
        sender_name: &str,
        ready_by: Option<f64>,
    ) -> Option<String> {
        let ll = link_local(mac)?;
        let knocked = knock(self, ll, port, ready_by);
        let (attempts, timeout) = lookup_budget(knocked);
        let sender = self.lookup_sender(sender_name);
        for attempt in 1..=attempts {
            let t0 = std::time::SystemTime::now();
            match &sender {
                Err(e) => {
                    trace(mac, attempt, knocked, t0, Some(1), Some(e));
                }
                Ok(sender) => match discover_once(sender, ll, port, timeout) {
                    Ok(name) => {
                        trace(mac, attempt, knocked, t0, Some(0), None);
                        return Some(name.unwrap_or_default());
                    }
                    Err((rc, err)) => trace(mac, attempt, knocked, t0, rc, Some(&err)),
                },
            }
        }
        None
    }

    fn sender_command(&self) -> Vec<String> {
        sender_command()
    }

    fn run_sender(&self, cmd: &[String]) -> i32 {
        let Some((prog, rest)) = cmd.split_first() else {
            return 1;
        };
        let mut child = match command(prog).args(rest).spawn() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("send-to-peer: cannot run {prog}: {e}");
                return 1;
            }
        };
        SENDER_PID.store(child.id(), Ordering::SeqCst);
        let status = child.wait();
        SENDER_PID.store(0, Ordering::SeqCst);
        match status {
            Ok(s) => {
                use std::os::unix::process::ExitStatusExt;
                s.code().unwrap_or_else(|| 128 + s.signal().unwrap_or(0))
            }
            Err(_) => 1,
        }
    }
}

/// Cancellation: SIGINT, SIGTERM and SIGHUP stop the advert and the sender
/// before this process goes. The default disposition would kill it without
/// unwinding, orphaning a radio that is transmitting (a Ctrl-C during
/// startup once left the advert running until its own --seconds expired).
///
/// The signals are blocked in every thread and taken by one thread with
/// sigwait. Children start with an empty mask ([`command`] clears it).
/// Call before any other thread exists.
pub fn install_signal_handling() {
    // SAFETY: sigset_t is plain data initialised by sigemptyset; the mask
    // calls only read it.
    let set = unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            libc::sigaddset(&mut set, sig);
        }
        if libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) != 0 {
            return;
        }
        set
    };
    let spawned = std::thread::Builder::new()
        .name("signals".into())
        .spawn(move || {
            let mut sig: libc::c_int = 0;
            // SAFETY: `set` is a valid initialised sigset; `sig` receives the number.
            if unsafe { libc::sigwait(&set, &mut sig) } != 0 {
                return;
            }
            stop_wake_child();
            stop_sender_child();
            if sig == libc::SIGTERM {
                // As Python's handler did: SystemExit(143).
                std::process::exit(143);
            }
            // SAFETY: restoring the default action and unblocking, then
            // re-raising, ends the process the way the signal would have.
            unsafe {
                libc::signal(sig, libc::SIG_DFL);
                let mut one: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut one);
                libc::sigaddset(&mut one, sig);
                libc::pthread_sigmask(libc::SIG_UNBLOCK, &one, std::ptr::null_mut());
                libc::raise(sig);
            }
            std::process::exit(128 + sig);
        });
    if spawned.is_err() {
        // No watcher thread: unblock again rather than ignore every signal.
        // SAFETY: as above.
        unsafe {
            libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
        }
    }
}
