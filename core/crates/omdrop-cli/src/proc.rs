//! Child processes the way the bash ran them: PATH lookups (so test stubs
//! apply), process groups that a cancel takes down whole, the TERM/INT/HUP
//! traps, line-at-a-time reading with deadlines, and the spinner.

use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::util::{exit, random_u64};

// ----------------------------------------------------------------- commands

/// What bash reports as `$?`: the exit code, or 128 + the signal.
pub fn code_of(status: ExitStatus) -> i32 {
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
}

/// Report a program that could not be started the way bash does, as 127.
fn spawn_failed(prog: &OsStr, e: &io::Error) -> i32 {
    errln!("omdrop: {}: {e}", prog.to_string_lossy());
    if e.kind() == io::ErrorKind::NotFound {
        127
    } else {
        126
    }
}

/// Run with stdout and stderr shared with ours; the exit status.
pub fn run<S: AsRef<OsStr>>(prog: impl AsRef<OsStr>, args: &[S]) -> i32 {
    let prog = prog.as_ref();
    match Command::new(prog).args(args).status() {
        Ok(s) => code_of(s),
        Err(e) => spawn_failed(prog, &e),
    }
}

/// `prog args >/dev/null 2>&1`.
pub fn run_quiet<S: AsRef<OsStr>>(prog: impl AsRef<OsStr>, args: &[S]) -> i32 {
    match Command::new(prog.as_ref())
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(s) => code_of(s),
        Err(e) if e.kind() == io::ErrorKind::NotFound => 127,
        Err(_) => 126,
    }
}

/// `prog args >/dev/null` (stderr still shown).
pub fn run_no_stdout<S: AsRef<OsStr>>(prog: impl AsRef<OsStr>, args: &[S]) -> i32 {
    let prog = prog.as_ref();
    match Command::new(prog).args(args).stdout(Stdio::null()).status() {
        Ok(s) => code_of(s),
        Err(e) => spawn_failed(prog, &e),
    }
}

/// How a child run by [`run_no_stdout_forwarding`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Forwarded {
    /// It exited by itself with this status.
    Exited(i32),
    /// A TERM, INT or HUP reached us and was passed on; the child then exited with this status.
    Cancelled(i32),
}

/// `prog args >/dev/null` with TERM, INT and HUP trapped from before the
/// spawn. A signal is passed on to the child alone, which owns undoing its
/// work: it is waited for, never killed, since a kill mid-undo leaves more
/// behind than a slow undo. The trap stays in place whichever way it ends,
/// so the caller decides when to [`untrap_signals`]. The child stays in our
/// process group, so a password prompt keeps the terminal and a Ctrl-C
/// reaches it directly.
pub fn run_no_stdout_forwarding<S: AsRef<OsStr>>(prog: impl AsRef<OsStr>, args: &[S]) -> Forwarded {
    let prog = prog.as_ref();
    trap_signals();
    let mut child = match Command::new(prog).args(args).stdout(Stdio::null()).spawn() {
        Ok(c) => c,
        Err(e) => return Forwarded::Exited(spawn_failed(prog, &e)),
    };
    let mut forwarded = false;
    loop {
        match child.try_wait() {
            Ok(Some(s)) if forwarded => return Forwarded::Cancelled(code_of(s)),
            Ok(Some(s)) => return Forwarded::Exited(code_of(s)),
            Ok(None) => {}
            Err(_) => return Forwarded::Exited(1),
        }
        if !forwarded && caught().is_some() {
            forwarded = true;
            if let Ok(pid) = i32::try_from(child.id()) {
                // SAFETY: kill(2) on our own unreaped child's pid.
                unsafe { libc::kill(pid, libc::SIGTERM) };
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Runs `cmd` until it exits or a trapped signal arrives: its status, or
/// `None` on a cancel, when the child is killed if it can be and left to
/// finish if not (a root helper), as `radio_up` leaves one.
pub fn run_unless_cancelled(cmd: &mut Command) -> Option<i32> {
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return Some(spawn_failed(cmd.get_program(), &e)),
    };
    loop {
        match child.try_wait() {
            Ok(Some(s)) => return Some(code_of(s)),
            Ok(None) => {}
            Err(_) => return Some(1),
        }
        if caught().is_some() {
            let _ = child.kill();
            let _ = child.try_wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// `$(prog args 2>/dev/null)`: the status and the raw output.
pub fn capture<S: AsRef<OsStr>>(prog: impl AsRef<OsStr>, args: &[S]) -> (i32, Vec<u8>) {
    capture_cmd(Command::new(prog.as_ref()).args(args).stderr(Stdio::null()))
}

/// `$(cmd 2>&1)`.
pub fn capture_merged(mut cmd: Command) -> (i32, Vec<u8>) {
    let Ok((read, write)) = pipe() else {
        return (126, Vec::new());
    };
    let Ok(write2) = write.try_clone() else {
        return (126, Vec::new());
    };
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::from(write))
        .stderr(Stdio::from(write2));
    let child = cmd.spawn();
    let prog = cmd.get_program().to_string_lossy().into_owned();
    drop(cmd);
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("omdrop: {prog}: {e}\n");
            return (
                if e.kind() == io::ErrorKind::NotFound {
                    127
                } else {
                    126
                },
                msg.into_bytes(),
            );
        }
    };
    let mut out = Vec::new();
    let _ = std::fs::File::from(read).read_to_end(&mut out);
    let code = child.wait().map(code_of).unwrap_or(1);
    (code, out)
}

pub fn capture_cmd(cmd: &mut Command) -> (i32, Vec<u8>) {
    match cmd.stdout(Stdio::piped()).output() {
        Ok(o) => (code_of(o.status), o.stdout),
        Err(e) if e.kind() == io::ErrorKind::NotFound => (127, Vec::new()),
        Err(_) => (126, Vec::new()),
    }
}

/// `$(prog args 2>/dev/null)` as text, trailing newlines stripped; `None`
/// when it failed.
pub fn capture_ok<S: AsRef<OsStr>>(prog: impl AsRef<OsStr>, args: &[S]) -> Option<String> {
    let (code, out) = capture(prog, args);
    (code == 0)
        .then(|| crate::util::strip_trailing_newlines(&String::from_utf8_lossy(&out)).to_string())
}

pub enum Captured {
    Done(i32, Vec<u8>),
    /// The deadline passed first; the whole group was stopped.
    TimedOut,
    /// More than the limit came; the whole group was stopped.
    TooLong,
}

/// `timeout LIMIT cmd 2>/dev/null` inside `$(...)`, but bounded end to end:
/// CMD leads a process group of its own, and at the deadline the whole
/// group goes, so a child still holding stdout open cannot keep us waiting.
/// The output is capped too, since nothing here needs more than `max`
/// bytes and a helper writing without end would otherwise fill memory
/// before any deadline. `None`: no deadline, as `timeout 0` has none.
pub fn capture_bounded(cmd: &mut Command, deadline: Option<Instant>, max: usize) -> Captured {
    let Ok((read, write)) = pipe() else {
        return Captured::Done(126, Vec::new());
    };
    cmd.stdin(Stdio::null())
        .stdout(Stdio::from(write))
        .stderr(Stdio::null());
    let spawned = spawn_group(cmd);
    // Our copy of the write end, so EOF comes when the group closes its own.
    cmd.stdout(Stdio::null());
    let mut child = match spawned {
        Ok(c) => c,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Captured::Done(127, Vec::new()),
        Err(_) => return Captured::Done(126, Vec::new()),
    };
    let mut file = std::fs::File::from(read);
    let mut out = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        if caught().is_some() {
            cancelled(Some(&mut child));
        }
        let mut wait = Duration::from_millis(100);
        if let Some(d) = deadline {
            let now = Instant::now();
            if now >= d {
                stop_group(&mut child);
                return Captured::TimedOut;
            }
            wait = wait.min(d - now);
        }
        let mut pfd = libc::pollfd {
            fd: file.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ms = i32::try_from(wait.as_millis()).unwrap_or(100).max(1);
        // SAFETY: one valid pollfd for the duration of the call.
        if unsafe { libc::poll(&mut pfd, 1, ms) } <= 0 {
            continue;
        }
        match file.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) if out.len() + n > max => {
                stop_group(&mut child);
                return Captured::TooLong;
            }
            Ok(n) => out.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    match wait_cancellable(&mut child, deadline) {
        Some(rc) => Captured::Done(rc, out),
        None => {
            stop_group(&mut child);
            Captured::TimedOut
        }
    }
}

/// A pipe whose ends are not inherited by anything else we start.
pub fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0i32; 2];
    // SAFETY: `fds` is a valid two-element array for pipe2 to fill.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pipe2 succeeded, so both descriptors are open and owned by us alone.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Run `f` with our stdout on /dev/null, as `cmd_off --force >/dev/null`
/// does to a shell function and everything it starts.
pub fn with_stdout_null<T>(f: impl FnOnce() -> T) -> T {
    let _ = io::stdout().flush();
    let Ok(null) = std::fs::OpenOptions::new().write(true).open("/dev/null") else {
        return f();
    };
    // SAFETY: F_DUPFD_CLOEXEC on fd 1 has no memory-safety requirements.
    let saved = unsafe { libc::fcntl(1, libc::F_DUPFD_CLOEXEC, 3) };
    if saved < 0 {
        return f();
    }
    // SAFETY: both descriptors are open; dup2 only replaces fd 1.
    unsafe { libc::dup2(null.as_raw_fd(), 1) };
    let result = f();
    let _ = io::stdout().flush();
    // SAFETY: `saved` is the descriptor duplicated above and still open.
    unsafe {
        libc::dup2(saved, 1);
        libc::close(saved);
    }
    result
}

// ------------------------------------------------------------------ signals

static CAUGHT: AtomicI32 = AtomicI32::new(0);
const TRAPPED: [i32; 3] = [libc::SIGTERM, libc::SIGINT, libc::SIGHUP];

extern "C" fn on_signal(sig: libc::c_int) {
    CAUGHT.store(sig, Ordering::SeqCst);
}

fn set_handler(handler: libc::sighandler_t) {
    for sig in TRAPPED {
        // SAFETY: a zeroed sigaction with an empty mask is valid; `handler`
        // is SIG_DFL or an async-signal-safe function that only stores an atomic.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = handler;
            libc::sigemptyset(&mut sa.sa_mask);
            sa.sa_flags = 0;
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
}

/// Set by [`hold_signals`]: an outer trap that inner traps must neither reset nor lift.
static HELD: AtomicBool = AtomicBool::new(false);

/// `trap '...' TERM INT HUP`: from here a signal is a flag to poll.
pub fn trap_signals() {
    if !HELD.load(Ordering::SeqCst) {
        CAUGHT.store(0, Ordering::SeqCst);
    }
    set_handler(on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t);
}

/// `trap - TERM INT HUP`. A signal that arrived after the last check still
/// gets the trap bash would have run for it. Under [`hold_signals`] the trap
/// stays, for the holder to act on.
pub fn untrap_signals() {
    if HELD.load(Ordering::SeqCst) {
        return;
    }
    if caught().is_some() {
        cancelled(None);
    }
    set_handler(libc::SIG_DFL);
}

/// A trap for work with an undo of its own: every inner trap keeps it and
/// every inner untrap leaves it, until [`release_signals_or`].
pub fn hold_signals() {
    trap_signals();
    HELD.store(true, Ordering::SeqCst);
}

/// Lifts [`hold_signals`]: back to the default action first, so a signal
/// that came before is seen here and runs `undo`, and one after is the
/// default's.
pub fn release_signals_or(undo: impl FnOnce()) {
    HELD.store(false, Ordering::SeqCst);
    set_handler(libc::SIG_DFL);
    if caught().is_some() {
        undo();
    }
}

/// Back to the default action, forgetting a signal that was already acted
/// on (the chooser closed itself and answers as a cancel).
pub fn untrap_forget() {
    set_handler(libc::SIG_DFL);
    CAUGHT.store(0, Ordering::SeqCst);
}

pub fn caught() -> Option<i32> {
    match CAUGHT.load(Ordering::SeqCst) {
        0 => None,
        s => Some(s),
    }
}

/// What every cancellable wait does when the person cancels.
pub fn cancelled(group: Option<&mut Child>) -> ! {
    if let Some(child) = group {
        stop_group(child);
    }
    spinner_restore_tty();
    errln!("Cancelled.");
    exit(130)
}

// ----------------------------------------------------------- process groups

/// Start `cmd` as the leader of a new process group (`set -m; cmd &`).
pub fn spawn_group(cmd: &mut Command) -> io::Result<Child> {
    cmd.process_group(0).spawn()
}

/// Start `cmd` in a session of its own (`setsid cmd`).
pub fn spawn_session(cmd: &mut Command) -> io::Result<Child> {
    // SAFETY: setsid is async-signal-safe and touches no memory of ours.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd.spawn()
}

/// TERM to the whole group, so the sender can take its Bluetooth advert down
/// itself, then KILL whatever is left after two seconds. Measured
/// 2026-09-23: a lookup given TERM stopped advertising but went on starting
/// probes for as long as it had peers to ask.
pub fn stop_group(child: &mut Child) {
    stop_group_within(child, Duration::from_secs(2));
}

/// TERM to the whole group, then KILL whatever is left after `grace`:
/// `timeout -k GRACE`, but for every process in the group.
pub fn stop_group_within(child: &mut Child, grace: Duration) {
    let Ok(pgid) = i32::try_from(child.id()) else {
        return;
    };
    // SAFETY: kill(2) with a negative pid signals that process group only.
    if unsafe { libc::kill(-pgid, libc::SIGTERM) } != 0 {
        let _ = child.try_wait();
        return;
    }
    let until = Instant::now() + grace;
    loop {
        // Reap the leader as it goes, or its zombie keeps the group "alive".
        let _ = child.try_wait();
        // SAFETY: as above, signal 0 only probes.
        if unsafe { libc::kill(-pgid, 0) } != 0 {
            // Empty and the leader reaped: the id may already be someone
            // else's group, so nothing more is sent to it.
            return;
        }
        if Instant::now() >= until {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // SAFETY: as above.
    unsafe { libc::kill(-pgid, libc::SIGKILL) };
    let _ = child.wait();
}

/// `timeout -k GRACE LIMIT cmd`, true when CMD exited 0 in time. CMD leads a
/// process group of its own, and at the deadline the whole group goes, so
/// nothing it started outlives the limit. `None`: no limit, as `timeout 0`.
pub fn run_bounded(cmd: &mut Command, limit: Option<Duration>, grace: Duration) -> bool {
    let Ok(mut child) = spawn_group(cmd) else {
        return false;
    };
    match wait_cancellable(&mut child, limit.map(|l| Instant::now() + l)) {
        Some(rc) => rc == 0,
        None => {
            stop_group_within(&mut child, grace);
            false
        }
    }
}

/// timeout(1)'s DURATION: a non-negative number with an optional s, m, h
/// or d. `Some(None)`: 0, no deadline. `None`: not a duration, which
/// timeout refuses, so nothing is run.
pub fn timeout_duration(text: &str) -> Option<Option<Duration>> {
    let (num, unit) = match text.strip_suffix(['s', 'm', 'h', 'd']) {
        Some(n) => (n, &text[n.len()..]),
        None => (text, "s"),
    };
    if num.is_empty() || !num.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return None;
    }
    let scale = match unit {
        "m" => 60.0,
        "h" => 3600.0,
        "d" => 86400.0,
        _ => 1.0,
    };
    let secs = num.parse::<f64>().ok()? * scale;
    let limit = Duration::try_from_secs_f64(secs).ok()?;
    Some((!limit.is_zero()).then_some(limit))
}

/// Wait for a child, polling for a cancel; `None` at the deadline.
pub fn wait_cancellable(child: &mut Child, deadline: Option<Instant>) -> Option<i32> {
    loop {
        match child.try_wait() {
            Ok(Some(s)) => return Some(code_of(s)),
            Ok(None) => {}
            Err(_) => return Some(1),
        }
        if caught().is_some() {
            cancelled(Some(child));
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// `run_cancellable CMD`: CMD as its own process group; TERM, INT or HUP
/// here takes the whole group down, says "Cancelled." and exits 130. Killed
/// while waiting on a pipeline, bash used to die and leave the sender
/// knocking on the device's door, and it would still have delivered the file.
pub fn run_cancellable(cmd: &mut Command) -> i32 {
    trap_signals();
    let mut child = match spawn_group(cmd) {
        Ok(c) => c,
        Err(e) => {
            untrap_signals();
            return spawn_failed(cmd.get_program(), &e);
        }
    };
    let rc = wait_cancellable(&mut child, None).unwrap_or(1);
    untrap_signals();
    rc
}

pub fn spawn_error(cmd: &Command, e: &io::Error) -> i32 {
    spawn_failed(cmd.get_program(), e)
}

// ------------------------------------------------------------ line reading

pub enum Read1 {
    Line(Vec<u8>),
    Eof,
    Timeout,
    /// A trapped TERM, INT or HUP arrived: the caller cancels.
    Signal,
}

/// Lines off a pipe, never blocking past a deadline or a cancel.
pub struct LineReader {
    file: std::fs::File,
    buf: Vec<u8>,
    eof: bool,
}

impl LineReader {
    pub fn new(fd: OwnedFd) -> Self {
        Self {
            file: std::fs::File::from(fd),
            buf: Vec::new(),
            eof: false,
        }
    }

    /// The next line without its newline. A last line with no newline still
    /// counts.
    pub fn read_line(&mut self, deadline: Option<Instant>) -> Read1 {
        loop {
            if let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
                let mut line: Vec<u8> = self.buf.drain(..=pos).collect();
                line.pop();
                return Read1::Line(line);
            }
            if self.eof {
                if self.buf.is_empty() {
                    return Read1::Eof;
                }
                return Read1::Line(std::mem::take(&mut self.buf));
            }
            if caught().is_some() {
                return Read1::Signal;
            }
            let mut wait = Duration::from_millis(100);
            if let Some(d) = deadline {
                let now = Instant::now();
                if now >= d {
                    return Read1::Timeout;
                }
                wait = wait.min(d - now);
            }
            let mut pfd = libc::pollfd {
                fd: self.file.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ms = i32::try_from(wait.as_millis()).unwrap_or(100).max(1);
            // SAFETY: one valid pollfd for the duration of the call.
            let n = unsafe { libc::poll(&mut pfd, 1, ms) };
            if n <= 0 {
                continue;
            }
            let mut chunk = [0u8; 8192];
            match self.file.read(&mut chunk) {
                Ok(0) => self.eof = true,
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => self.eof = true,
            }
        }
    }
}

// ------------------------------------------------------------------ spinner

/// Braille frames, because they are one column wide in every terminal font
/// we have; a multi-column glyph leaves droppings when the line is erased.
/// The verbs rotate every few seconds: a frame that spins but never changes
/// its words looks the same whether the command is working or wedged, and
/// the elapsed counter beside them is what actually answers "is this hung".
const FRAMES: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
const VERBS: [&str; 14] = [
    "Hollering",
    "Eavesdropping",
    "Doorknocking",
    "Wheedling",
    "Coaxing",
    "Cajoling",
    "Rummaging",
    "Earwigging",
    "Loitering",
    "Dowsing",
    "Beachcombing",
    "Wittering",
    "Pestering",
    "Hobnobbing",
];

struct Running {
    stop: Arc<AtomicBool>,
    thread: std::thread::JoinHandle<()>,
    tty: std::fs::File,
}

static SPINNER: Mutex<Option<Running>> = Mutex::new(None);

/// A live "still working" line on /dev/tty -- NOT stdout or stderr, both of
/// which callers parse -- while a slow command runs. Nothing when there is
/// no terminal. Opening it is the test: /dev/tty is world-writable whether or
/// not this process has a controlling terminal, so its mode says nothing.
pub fn spinner_start(label: &str) {
    let Ok(tty) = std::fs::OpenOptions::new().write(true).open("/dev/tty") else {
        return;
    };
    let Ok(mut draw) = tty.try_clone() else {
        return;
    };
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let label = label.to_string();
    let first = (random_u64() % VERBS.len() as u64) as usize;
    let thread = std::thread::spawn(move || {
        let start = Instant::now();
        let _ = draw.write_all(b"\x1b[?25l");
        let mut i = 0usize;
        while !flag.load(Ordering::SeqCst) {
            let now = start.elapsed().as_secs();
            let verb = VERBS[(first + (now / 4) as usize) % VERBS.len()];
            let _ = write!(
                draw,
                "\r\x1b[K{} {verb}… ({now}s · {label})",
                FRAMES[i % FRAMES.len()]
            );
            i += 1;
            std::thread::sleep(Duration::from_millis(100));
        }
    });
    if let Ok(mut slot) = SPINNER.lock() {
        *slot = Some(Running { stop, thread, tty });
    }
}

/// Erase the line and give the cursor back, however we end: a hidden cursor
/// left behind outlives the command and breaks the terminal.
pub fn spinner_restore_tty() {
    let running = SPINNER.lock().ok().and_then(|mut slot| slot.take());
    if let Some(mut r) = running {
        r.stop.store(true, Ordering::SeqCst);
        let _ = r.thread.join();
        let _ = r.tty.write_all(b"\r\x1b[K\x1b[?25h");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_timeout_reads_as_timeout_reads_it() {
        assert_eq!(timeout_duration("5"), Some(Some(Duration::from_secs(5))));
        assert_eq!(
            timeout_duration("0.5"),
            Some(Some(Duration::from_millis(500)))
        );
        assert_eq!(timeout_duration("2m"), Some(Some(Duration::from_secs(120))));
        assert_eq!(timeout_duration("1s"), Some(Some(Duration::from_secs(1))));
        assert_eq!(timeout_duration("0"), Some(None));
        for bad in ["", "s", "-1", "five", "1x", "1.2.3", "inf", "1e3"] {
            assert_eq!(timeout_duration(bad), None, "{bad}");
        }
    }
}
