//! The discoverability window: start, the supervisor, stop and status.
//!
//! Run-directory state is read and written only through `Ctx` (rundir.rs):
//! fd-relative, no symlinks, and a file counts only when it is root-owned and
//! not writable by group or others. A process is signalled only when its
//! identity is proven: start time, argv and uid for a pid, the group leader's
//! start time for a process group.

use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::ctx::{Ctx, Exit, IFACE, Res, clock, exit, is_duration, is_uint, now};
use crate::net;
use crate::proc::{self, Opts, Outcome, Pidfd};

/// Receiver capability flags in the AirDrop advert and the mDNS TXT record.
/// 0x88 is OpenDrop's set (SUPPORTS_MIXED_TYPES | SUPPORTS_DISCOVER_MAYBE);
/// 0x89 adds SUPPORTS_URL, the standing suspect for iOS 26 accepting a links
/// Ask and never uploading (2026-09-12), with MIXED_TYPES kept so sharingd's
/// removeInvalidNodes: still considers us a valid node.
const ADV_FLAGS: &str = "137";
const RECEIVER_PORT: &str = "8771";

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const UP_TIMEOUT: Duration = Duration::from_secs(300);
const IDENTITY_TIMEOUT: Duration = Duration::from_secs(120);
const TICK_TIMEOUT: Duration = Duration::from_secs(60);
const DOWN_TIMEOUT: Duration = Duration::from_secs(60);
/// How long teardown waits for killed children before leaving them be.
const REAP: Duration = Duration::from_secs(5);
/// How long a `start` or a supervisor waits for `window.lock`. Its holders
/// only read and write state files under it.
const WINDOW_LOCK_WAIT: Duration = Duration::from_secs(10);
/// How long a start waits for the driver's boot-time warm-up (awdl-warmup),
/// which holds the start lock while its gate runs.
const WARMUP_WAIT: Duration = Duration::from_secs(180);
/// How long a start that finds the start lock held looks for the warm-up
/// before taking the holder for another start. The warm-up writes `warmup`
/// just after it takes the lock and removes it just before it lets go, so one
/// look can miss it.
const WARMUP_HANDOFF: Duration = Duration::from_secs(2);
/// How long a `start` waits for a supervisor that is ending its window. Its
/// teardown is bounded at about 75 s: a second between TERM and KILL for its
/// children, REAP for them, then `down` (DOWN_TIMEOUT, plus the TERM grace,
/// KILL wait and pipe drain proc::hook allows).
const CLOSING_WAIT: Duration = Duration::from_secs(90);

pub fn need_root(ctx: &Ctx, args: &[&str]) -> Result<(), Exit> {
    if ctx.is_privileged() {
        return Ok(());
    }
    Err(exit(
        2,
        format!("needs root: pkexec {} {}", ctx.self_str(), args.join(" ")),
    ))
}

fn opts(timeout: Duration) -> Opts {
    Opts {
        timeout,
        stdout: None,
        log_stderr: true,
        cancellable: true,
        record: false,
    }
}

// --- announce settings ------------------------------------------------------

/// The announcer burst and supervisor interval. 40 frames per interval is what
/// reaches Apple devices through 4 active slots of 16 (~25% make the air).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announce {
    pub count: u64,
    pub interval_us: u64,
    pub period_s: u64,
    pub plain: bool,
    pub mdns: bool,
}

impl Default for Announce {
    fn default() -> Self {
        Announce {
            count: 40,
            interval_us: 20_000,
            period_s: 6,
            plain: false,
            mdns: true,
        }
    }
}

impl Announce {
    fn from_up_stdout(ctx: &mut Ctx, out: &[u8]) -> Announce {
        let mut a = Announce::default();
        let text = String::from_utf8_lossy(out);
        if text.trim().is_empty() {
            return a;
        }
        let Ok(serde_json::Value::Object(v)) =
            serde_json::from_str::<serde_json::Value>(text.trim())
        else {
            ctx.log("up: stdout is not a JSON object; using the default announcer");
            return a;
        };
        let mut bad = Vec::new();
        if let Some(m) = v.get("mdns") {
            match m.as_bool() {
                Some(b) => a.mdns = b,
                None => bad.push("mdns"),
            }
        }
        if let Some(an) = v.get("announce") {
            let Some(an) = an.as_object() else {
                ctx.log("up: announce is not an object; using the default announcer");
                return a;
            };
            let mut num = |key: &'static str, lo: u64, hi: u64, slot: &mut u64| {
                if let Some(x) = an.get(key) {
                    match x.as_u64().filter(|n| (lo..=hi).contains(n)) {
                        Some(n) => *slot = n,
                        None => bad.push(key),
                    }
                }
            };
            num("count", 1, 256, &mut a.count);
            num("interval_us", 1000, 1_000_000, &mut a.interval_us);
            num("period_s", 1, 60, &mut a.period_s);
            if let Some(p) = an.get("plain") {
                match p.as_bool() {
                    Some(b) => a.plain = b,
                    None => bad.push("plain"),
                }
            }
        }
        if !bad.is_empty() {
            ctx.log(&format!(
                "up: ignored invalid {}; using defaults for them",
                bad.join(", ")
            ));
        }
        a
    }

    fn line(&self) -> String {
        format!(
            "{} {} {} {} {}\n",
            self.count, self.interval_us, self.period_s, self.plain as u8, self.mdns as u8
        )
    }

    /// Re-validated on read: the file is root-owned, but nothing here depends
    /// on where its numbers came from.
    fn parse(s: Option<String>) -> Announce {
        let d = Announce::default();
        let Some(s) = s else { return d };
        let f: Vec<&str> = s.split_whitespace().collect();
        let num = |i: usize, lo: u64, hi: u64| {
            f.get(i)
                .filter(|x| is_uint(x))
                .and_then(|x| x.parse::<u64>().ok())
                .filter(|n| (lo..=hi).contains(n))
        };
        let flag = |i: usize| match f.get(i) {
            Some(&"1") => Some(true),
            Some(&"0") => Some(false),
            _ => None,
        };
        match (
            num(0, 1, 256),
            num(1, 1000, 1_000_000),
            num(2, 1, 60),
            flag(3),
            flag(4),
        ) {
            (Some(count), Some(interval_us), Some(period_s), Some(plain), Some(mdns))
                if f.len() == 5 =>
            {
                Announce {
                    count,
                    interval_us,
                    period_s,
                    plain,
                    mdns,
                }
            }
            _ => d,
        }
    }

    /// Seconds as the announcer's argparse float: 20000 -> "0.02".
    fn interval_arg(&self) -> String {
        let s = format!(
            "{}.{:06}",
            self.interval_us / 1_000_000,
            self.interval_us % 1_000_000
        );
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    }
}

// --- process identity -------------------------------------------------------

/// `<pid> <start time>`, both canonical decimal, nothing else.
fn parse_pid_start(s: &str) -> Option<(u32, u64)> {
    let mut f = s.split_whitespace();
    let pid = f.next().filter(|p| is_uint(p))?.parse::<u32>().ok()?;
    let start = f.next().filter(|p| is_uint(p))?.parse::<u64>().ok()?;
    (pid > 1 && f.next().is_none()).then_some((pid, start))
}

fn legacy_exe(ctx: &Ctx) -> PathBuf {
    ctx.paths.legacy.join("omdrop-discoverable")
}

fn adv_path(ctx: &Ctx) -> Option<PathBuf> {
    Some(ctx.self_exe.parent()?.join("omdrop-adv"))
}

/// A supervisor of ours at `pid`: argv `<omdrop-radio> __supervise ...` by
/// position, running as root.
fn is_our_supervisor(ctx: &Ctx, pid: u32) -> bool {
    proc::is_invocation(pid, &ctx.self_exe, "__supervise")
        && proc::owned_by(pid, ctx.trusted_owner())
        && proc::running(pid)
}

/// 0.9.x's supervisor as /proc shows it: `bash <omdrop-discoverable>
/// __supervise ...` (its `#!/usr/bin/env bash` exec).
fn is_legacy_supervisor(legacy: &Path, pid: u32) -> bool {
    proc::is_script_run(pid, &["bash", "sh"], legacy, Some("__supervise"))
}

/// `pid` is `ancestor` or below it.
fn descends_from(mut pid: u32, ancestor: u32) -> bool {
    for _ in 0..64 {
        if pid == ancestor {
            return true;
        }
        match proc::ppid(pid) {
            Some(p) if p > 1 => pid = p,
            _ => return false,
        }
    }
    false
}

/// The recorded supervisor is alive and really is ours: same start time,
/// argv and uid. Through /proc, not kill(0): status runs unprivileged, and
/// signalling a root process fails with EPERM, which once reported a live
/// window as expired.
fn supervisor_alive(ctx: &Ctx) -> bool {
    let Some((pid, start)) = ctx.state("supervisor").as_deref().and_then(parse_pid_start) else {
        return false;
    };
    proc::start_time(pid) == Some(start) && is_our_supervisor(ctx, pid)
}

/// The recorded supervisor as a handle, while it is alive and ours (as
/// supervisor_alive judges it), so waiting for it never trusts a pid twice.
fn recorded_supervisor(ctx: &Ctx) -> Option<Pidfd> {
    let (pid, start) = ctx
        .state("supervisor")
        .as_deref()
        .and_then(parse_pid_start)?;
    let (exe, owner) = (ctx.self_exe.clone(), ctx.trusted_owner());
    Pidfd::open(pid, move |p| {
        proc::start_time(p) == Some(start)
            && proc::is_invocation(p, &exe, "__supervise")
            && proc::owned_by(p, owner)
            && proc::running(p)
    })
}

/// `until` is a deadline still ahead, or 0 (until stopped).
fn until_live(ctx: &Ctx) -> bool {
    ctx.state("until")
        .filter(|d| is_uint(d))
        .and_then(|d| d.parse::<u64>().ok())
        .is_some_and(|d| d == 0 || now() < d)
}

/// Whether the driver's boot-time warm-up holds the start lock: it records its
/// pid in `warmup` while it runs. Its comm is the interpreter's, so its command
/// line is what names it; a reused pid fails this.
fn warmup_running(ctx: &Ctx) -> bool {
    ctx.state("warmup")
        .and_then(|p| p.parse::<u32>().ok())
        .is_some_and(|pid| {
            proc::cmdline(pid)
                .iter()
                .any(|a| a.rsplit(|&b| b == b'/').next() == Some(b"awdl-warmup".as_slice()))
        })
}

/// Called with the start lock held by someone else: looks for the warm-up for
/// up to [`WARMUP_HANDOFF`], or for the lock coming free. True when this start
/// took the lock. It names itself in `warmup` only while it holds the lock, so
/// a warm-up queued behind an ordinary start never makes a start wait for that
/// one; the moments before it writes the file and after it removes it are
/// what the look covers.
fn warmup_handed_over(ctx: &Ctx, try_lock: &dyn Fn() -> bool) -> bool {
    let end = Instant::now() + WARMUP_HANDOFF;
    while !warmup_running(ctx) && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(50));
        if try_lock() {
            return true;
        }
    }
    false
}

/// `window.lock`, held by a `start` while it looks at a window and extends
/// it, and by the supervisor while it decides to end one (end_window). It is
/// opened O_CLOEXEC, so no hook or child ever holds it.
fn window_lock(ctx: &Ctx) -> Result<std::fs::File, String> {
    let f = ctx
        .rd
        .as_ref()
        .ok_or("the run directory is not open")?
        .append("window.lock")
        .map_err(|e| format!("cannot open the window lock: {e}"))?;
    let end = Instant::now() + WINDOW_LOCK_WAIT;
    // SAFETY: flock on a descriptor we own; released when `f` closes.
    while unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let e = std::io::Error::last_os_error();
        if !matches!(e.raw_os_error(), Some(libc::EWOULDBLOCK | libc::EINTR)) {
            return Err(format!("cannot take the window lock: {e}"));
        }
        if Instant::now() >= end {
            return Err(format!(
                "the window lock has been held for over {} s",
                WINDOW_LOCK_WAIT.as_secs()
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(f)
}

/// The supervisor's decision to end its window, made under `window.lock`:
/// `until` goes first, so every `start` from then on finds the window closing
/// and waits for this supervisor to exit. On expiry `until` is read again
/// under the lock, and a deadline a `start` moved meanwhile keeps the window
/// open (returns false).
fn end_window(ctx: &mut Ctx, expiry: bool) -> bool {
    let _window = window_lock(ctx)
        .map_err(|e| ctx.log(&format!("{e}; ending the window without it")))
        .ok();
    if expiry && until_live(ctx) {
        return false;
    }
    ctx.unset("until");
    true
}

/// Live supervisors of omdrop-awdl 0.9.x's omdrop-discoverable. It shares the
/// run directory, so its window is the window: status reports it, start does
/// not open a second one over it, and stop ends it. Only the one 0.9.x
/// recorded in `supervisor` (a bare pid) counts, with any of its subshells:
/// argv alone can be put on any process, root's included (0.9.x's `diag`
/// ignores extra arguments).
fn legacy_supervisors(ctx: &Ctx) -> Vec<u32> {
    let Some(rec) = ctx
        .state("supervisor")
        .filter(|s| is_uint(s))
        .and_then(|s| s.parse::<u32>().ok())
        .filter(|p| *p > 1)
    else {
        return Vec::new();
    };
    let legacy = legacy_exe(ctx);
    proc::find(ctx.trusted_owner(), |p| {
        is_legacy_supervisor(&legacy, p) && descends_from(p, rec)
    })
}

/// What a `pids` line names.
struct Recorded {
    pid: u32,
    tag: String,
    start: Option<u64>,
}

fn parse_pids(text: &str) -> Vec<Recorded> {
    text.lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let pid = f
                .next()
                .filter(|p| is_uint(p))?
                .parse::<u32>()
                .ok()
                .filter(|p| *p > 1)?;
            let tag = f.next().unwrap_or("").to_string();
            let start = f.next().filter(|s| is_uint(s)).and_then(|s| s.parse().ok());
            Some(Recorded { pid, tag, start })
        })
        .collect()
}

/// The program a child with this tag runs, in this helper or in 0.9.x's.
fn runs_tagged_program(ctx: &Ctx, pid: u32, tag: &str) -> bool {
    let legacy = |script: &str| {
        proc::is_script_run(
            pid,
            &["python3", "python"],
            &ctx.paths.legacy.join(script),
            None,
        )
    };
    let ours = |verb: &str| adv_path(ctx).is_some_and(|a| proc::is_invocation(pid, &a, verb));
    match tag {
        "mdns" => ours("mdns") || legacy("awdl-mdns-respond.py"),
        "ble" => ours("ble") || legacy("ble-airdrop-adv.py"),
        "peers" => {
            proc::is_script_run(
                pid,
                &["bash", "sh"],
                &ctx.paths.hooks.join("peer-watch"),
                None,
            ) || legacy("awdl-peer-watch.py")
        }
        _ => false,
    }
}

/// The signal target for a recorded child, if it is provably the process we
/// started. A line with a start time names a process group whose leader must
/// still have that start time. A line without one (0.9.x's format) names a
/// single pid, signalled only if it still runs the program for its tag. Both
/// must run as root. Anything else is left alone: a `pids` file from a dead
/// supervisor can outlive its processes, and pids are reused.
fn still_ours(ctx: &Ctx, r: &Recorded) -> Option<i32> {
    if !proc::owned_by(r.pid, ctx.trusted_owner()) || !proc::running(r.pid) {
        return None;
    }
    match r.start {
        Some(st) => (proc::start_time(r.pid) == Some(st) && proc::pgrp(r.pid) == Some(r.pid))
            .then(|| -(r.pid as i32)),
        None => runs_tagged_program(ctx, r.pid, &r.tag).then_some(r.pid as i32),
    }
}

/// Kill every recorded child, as a group, exactly once. Two teardowns can run
/// at once (`stop` and the supervisor's own), and the rename decides which:
/// the winner takes the list, the loser finds no file and returns.
fn kill_children(ctx: &mut Ctx) {
    let snapshot = format!("pids.dying.{}", std::process::id());
    let list = {
        let Some(rd) = ctx.rd.as_ref() else { return };
        if !rd.exists("pids") || rd.rename("pids", &snapshot).is_err() {
            return;
        }
        let text = rd.read_max(&snapshot, 64 << 10);
        rd.remove(&snapshot);
        parse_pids(&text.unwrap_or_default())
    };
    let mut targets = Vec::new();
    for r in &list {
        if let Some(target) = still_ours(ctx, r)
            && proc::signal(target, libc::SIGTERM)
        {
            ctx.log(&format!("stopped {} (pid {})", r.tag, r.pid));
            targets.push((r, target));
        }
    }
    if !targets.is_empty() {
        std::thread::sleep(Duration::from_secs(1));
        for (r, target) in targets {
            if still_ours(ctx, r) == Some(target) {
                proc::signal(target, libc::SIGKILL);
            }
        }
    }
}

/// Wait for a child we killed, but not forever: one in uninterruptible sleep
/// is left to a detached reaper.
fn reap(ctx: &mut Ctx, tag: &str, mut c: Child, until: Instant) {
    loop {
        if !matches!(c.try_wait(), Ok(None)) {
            return;
        }
        if Instant::now() >= until {
            ctx.log(&format!(
                "{tag} (pid {}) did not exit after SIGKILL; no longer waiting",
                c.id()
            ));
            std::thread::spawn(move || {
                let _ = c.wait();
            });
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Start a window child in its own process group, logging to `<tag>.log`,
/// and record it for kill_children. A child that cannot be recorded is
/// killed at once: nothing else could stop it.
fn spawn(ctx: &mut Ctx, tag: &str, program: &Path, args: &[String]) -> Option<Child> {
    let log = ctx.rd.as_ref().map(|rd| rd.append(&format!("{tag}.log")));
    let (out, err) = match log {
        Some(Ok(f)) => match f.try_clone() {
            Ok(g) => (Stdio::from(g), Stdio::from(f)),
            Err(_) => (Stdio::null(), Stdio::null()),
        },
        _ => (Stdio::null(), Stdio::null()),
    };
    let child = Command::new(program)
        .args(args)
        .env_clear()
        .envs(ctx.child_env())
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(out)
        .stderr(err)
        .process_group(0)
        .spawn();
    let c = match child {
        Ok(c) => c,
        Err(e) => {
            ctx.log(&format!(
                "could not start {tag}: {}: {e}",
                program.display()
            ));
            return None;
        }
    };
    let pid = c.id();
    let recorded = match (proc::start_time(pid), ctx.rd.as_ref()) {
        (Some(st), Some(rd)) => rd
            .append("pids")
            .and_then(|mut f| writeln!(f, "{pid} {tag} {st}"))
            .is_ok(),
        _ => false,
    };
    if !recorded {
        proc::signal(-(pid as i32), libc::SIGKILL);
        ctx.log(&format!(
            "could not record {tag} (pid {pid}) in pids; stopped it"
        ));
        reap(ctx, tag, c, Instant::now() + REAP);
        return None;
    }
    ctx.log(&format!("started {tag} (pid {pid})"));
    Some(c)
}

/// `omdrop-adv` beside our own executable, if it passes the ownership check.
fn adv(ctx: &mut Ctx) -> Option<PathBuf> {
    let p = adv_path(ctx)?;
    match crate::ctx::trusted(&p, ctx.trusted_owner()) {
        Ok(()) => Some(p),
        Err(e) => {
            ctx.log(&format!("advertiser not run: {e}"));
            None
        }
    }
}

fn down(ctx: &mut Ctx, why: &str, record: bool) {
    let o = Opts {
        cancellable: false,
        record,
        ..opts(DOWN_TIMEOUT)
    };
    match proc::hook(ctx, "down", &[why], o).outcome {
        Outcome::Exited(0) | Outcome::Missing => {}
        o => ctx.log(&format!("down {why}: {}", o.describe())),
    }
}

/// A hook a supervisor was running when it was SIGKILLed: its process group
/// is recorded in `hook.pgid`, and killed here if its leader is provably the
/// process recorded.
fn kill_orphaned_hook(ctx: &mut Ctx) {
    let Some((pgid, start)) = ctx.state("hook.pgid").as_deref().and_then(parse_pid_start) else {
        ctx.unset("hook.pgid");
        return;
    };
    ctx.unset("hook.pgid");
    let owner = ctx.trusted_owner();
    let leader = Pidfd::open(pgid, move |p| {
        proc::start_time(p) == Some(start) && proc::pgrp(p) == Some(p) && proc::owned_by(p, owner)
    });
    let Some(leader) = leader else { return };
    proc::signal(-(pgid as i32), libc::SIGTERM);
    ctx.log(&format!(
        "stopped an orphaned radio hook (process group {pgid})"
    ));
    // Whatever of the group outlived TERM goes too, leader or not. While any
    // member remains the pgid cannot be reused; ESRCH means it is empty.
    proc::wait_exited(std::slice::from_ref(&leader), Duration::from_secs(2));
    proc::signal(-(pgid as i32), libc::SIGKILL);
}

/// Sampled every interval: two file reads until the window is proven, nothing
/// afterwards. The gate proves TRANSMIT only; the receive half parks
/// independently (00:23-00:30Z: 20/20 completions and seven minutes of zero
/// data frames), and an empty room cannot prove it, so no start waits for it.
fn rx_watch(ctx: &mut Ctx) {
    if ctx.state("rx_proven").as_deref() == Some("1") {
        return;
    }
    let base = ctx
        .state("rx_base")
        .filter(|b| is_uint(b))
        .and_then(|b| b.parse::<u64>().ok());
    let Some(base) = base else {
        ctx.set("rx_base", &net::rx_packets(ctx).to_string());
        return;
    };
    if net::rx_packets(ctx) > base {
        ctx.set("rx_proven", "1");
        ctx.log("receive confirmed: data frames arriving");
    }
}

// --- start ------------------------------------------------------------------

/// The probe as `start` needs it: a backend that speaks this contract and
/// has hardware to drive.
fn check_backend(ctx: &mut Ctx) -> Result<(), Exit> {
    let o = Opts {
        stdout: Some(64 << 10),
        ..opts(PROBE_TIMEOUT)
    };
    let r = proc::hook(ctx, "probe", &["--json"], o);
    let none = "AirDrop's radio backend is not installed, so this machine cannot be discovered.";
    match r.outcome {
        Outcome::Exited(0) => {}
        Outcome::Missing => {
            ctx.log(&format!(
                "no radio backend hooks in {}",
                ctx.paths.hooks.display()
            ));
            return Err(exit(4, none));
        }
        Outcome::Cancelled => return Err(exit(3, "start cancelled")),
        o => {
            ctx.log(&format!("probe: {}", o.describe()));
            return Err(exit(
                4,
                "AirDrop's radio backend did not answer. Reinstalling or updating it may help.",
            ));
        }
    }
    let probe = crate::diag::parse_probe(&r.stdout).ok_or_else(|| {
        exit(
            4,
            "AirDrop's radio backend answered something omdrop cannot read. Updating it may help.",
        )
    })?;
    if probe.hooks != Some(1) {
        return Err(exit(
            4,
            format!(
                "The installed radio backend ({}) follows a different version of omdrop's backend contract. Update it.",
                probe.backend
            ),
        ));
    }
    if probe.hardware == Some(false) {
        let say = probe.first_missing.unwrap_or_else(|| {
            format!(
                "This computer's Wi-Fi is not one the installed radio backend ({}) can drive.",
                probe.backend
            )
        });
        return Err(exit(4, say));
    }
    Ok(())
}

/// After a failed `up` or anything later: undo, then make the sentence a
/// person reads the last line again (down may have logged after it).
fn fail_start(
    ctx: &mut Ctx,
    reason: &str,
    code: i32,
    said: Option<String>,
    fallback: &str,
) -> Exit {
    if !reason.is_empty() {
        ctx.set("reason", reason);
    }
    let sentence = match said {
        Some(s) => s,
        None => {
            ctx.log(fallback);
            ctx.last_stderr.clone().unwrap_or_default()
        }
    };
    down(ctx, "start-failed", true);
    ctx.repeat_last(&sentence);
    exit(code, "")
}

pub fn start(ctx: &mut Ctx, args: &[String]) -> Res {
    let usage = || {
        exit(
            2,
            format!(
                "usage: {} start <seconds> (0 = until stopped, at most 999999999)",
                ctx.self_str()
            ),
        )
    };
    let [secs] = args else {
        return Err(usage());
    };
    // 0 is a window with no expiry: the panel's "Until I turn it off" sends it.
    if !is_duration(secs) {
        return Err(usage());
    }
    need_root(ctx, &["start", secs])?;
    let secs_n: u64 = secs.parse().map_err(|_| usage())?;
    ctx.mkdir_run()?;
    // One start at a time: two presses seconds apart put two starts in the
    // gate at once, toggling awdl=0/1 under each other (00:16-00:17Z).
    let lock = ctx
        .rd
        .as_ref()
        .map(|rd| rd.append("start.lock"))
        .transpose()
        .map_err(|e| exit(3, format!("cannot open the start lock: {e}")))?
        .ok_or_else(|| exit(3, "the run directory is not open"))?;
    // SAFETY: the fd is valid for the lifetime of `lock`; the lock is released
    // when it closes. It is opened O_CLOEXEC, so the supervisor never holds it.
    let try_lock = || unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0;
    if !try_lock() && !warmup_handed_over(ctx, &try_lock) {
        // The driver's boot-time warm-up holds the lock for its gate. A window
        // opened right after login waits for it rather than failing; once it
        // ends, this start's first probe passes.
        if !warmup_running(ctx) {
            ctx.log("another start is already in its gate; not racing it");
            return Ok(5);
        }
        ctx.log("waiting for the boot-time warm-up to finish");
        let end = Instant::now() + WARMUP_WAIT;
        while !try_lock() {
            if Instant::now() >= end {
                // 3, not 5: no window opened, and 5 reads as "already
                // starting or visible" to callers.
                ctx.log(&format!(
                    "the boot-time warm-up held the start lock for {} s; try again",
                    WARMUP_WAIT.as_secs()
                ));
                return Ok(3);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    proc::catch_termination();

    if !legacy_supervisors(ctx).is_empty() {
        // Its children are its own; killing them, or toggling the radio under
        // it, would break a working window.
        ctx.log("AirDrop is already discoverable through the older omdrop-discoverable helper. Turn it off before turning it on again.");
        return Ok(5);
    }
    // The supervisor ends its window under `window.lock`, removing `until`
    // first (end_window). Under the same lock, a deadline written here is one
    // it will read, and a live supervisor without one is closing: wait for it
    // and open a new window, never report an extension it is about to undo.
    let closing = {
        let _window = window_lock(ctx).map_err(|e| exit(3, e))?;
        match recorded_supervisor(ctx) {
            Some(sup) if !ctx.state("until").is_some_and(|d| is_uint(&d)) => Some(sup),
            Some(_) => {
                // A live supervisor re-reads `until` every interval, so
                // rewriting it is how a second press moves the deadline,
                // including to 0.
                if secs_n > 0 {
                    let until = now() + secs_n;
                    ctx.set("until", &format!("{until}\n"));
                    ctx.log(&format!(
                        "already discoverable; window extended to {}",
                        clock(until)
                    ));
                } else {
                    ctx.set("until", "0");
                    ctx.log("already discoverable; window now runs until turned off");
                }
                ctx.set("reason", "ok");
                return Ok(5);
            }
            None => None,
        }
    };
    if let Some(sup) = closing {
        ctx.log("the window is closing; opening a new one once it has closed");
        let end = Instant::now() + CLOSING_WAIT;
        while !sup.exited() {
            if Instant::now() >= end {
                return Err(exit(
                    3,
                    "AirDrop's previous window is still closing. Try again in a moment.",
                ));
            }
            if !proc::sleep(Duration::from_millis(50)) {
                ctx.log("start cancelled while the previous window was closing");
                return Ok(3);
            }
        }
    }
    // A dead supervisor may still have left children (SIGKILL, crash), and
    // the hook it was running.
    kill_orphaned_hook(ctx);
    kill_children(ctx);
    if let Err(e) = check_backend(ctx) {
        if e.code == 4 {
            ctx.set("reason", "no_awdl0");
        }
        return Err(e);
    }

    ctx.set("rx_proven", "0");
    ctx.unset("rx_base");
    let o = Opts {
        stdout: Some(64 << 10),
        record: true,
        ..opts(UP_TIMEOUT)
    };
    let r = proc::hook(ctx, "up", &[], o);
    let said = r.said.then(|| ctx.last_stderr.clone()).flatten();
    match r.outcome {
        Outcome::Exited(0) => {}
        Outcome::Cancelled => {
            // `stop` cancelled us; it tears down and writes the reason.
            ctx.log("start cancelled while the radio was coming up");
            return Ok(3);
        }
        Outcome::Exited(4) => {
            return Err(fail_start(
                ctx,
                "no_awdl0",
                4,
                said,
                "AirDrop's radio interface could not be started. Turning Wi-Fi off and back on usually clears this; a restart always does.",
            ));
        }
        Outcome::Missing | Outcome::Broken(_) => {
            if r.outcome == Outcome::Missing {
                ctx.log(&format!(
                    "the radio backend has no up hook in {}",
                    ctx.paths.hooks.display()
                ));
            }
            ctx.set("reason", "no_awdl0");
            return Err(exit(
                4,
                "AirDrop's radio backend is not installed, so this machine cannot be discovered.",
            ));
        }
        o => {
            if !matches!(o, Outcome::Exited(3)) {
                ctx.log(&format!("up: {}", o.describe()));
            }
            let said = if matches!(o, Outcome::Exited(3)) {
                said
            } else {
                None
            };
            return Err(fail_start(
                ctx,
                "parked",
                3,
                said,
                "AirDrop's radio did not answer a test. Try again in a moment.",
            ));
        }
    }
    let announce = Announce::from_up_stdout(ctx, &r.stdout);
    ctx.set("announce", &announce.line());
    // Require the address a sender must reach before claiming the window, so
    // a dead netdev reports no_awdl0 instead of lying with ok (07:57:30Z).
    if !net::has_link_local(ctx) {
        ctx.log(&format!(
            "the radio backend reported {IFACE} up, but it has no IPv6 link-local address"
        ));
        return Err(fail_start(
            ctx,
            "no_awdl0",
            4,
            None,
            "awdl0 has no link-local address after the radio came up -- nothing can bind to it",
        ));
    }
    ctx.set("rx_base", &net::rx_packets(ctx).to_string());

    let o = Opts {
        record: true,
        ..opts(IDENTITY_TIMEOUT)
    };
    match proc::hook(ctx, "identity", &[], o).outcome {
        Outcome::Exited(0) | Outcome::Missing => {}
        Outcome::Cancelled => {
            ctx.log("start cancelled while publishing the identity");
            return Ok(3);
        }
        o => ctx.log(&format!("identity: {}", o.describe())),
    }
    // A stop that arrived while the hook ran has already torn down; writing
    // the window's state now would leave a live `until` with no supervisor.
    if proc::cancelled() {
        ctx.log("start cancelled while publishing the identity");
        return Ok(3);
    }
    let until = if secs_n > 0 { now() + secs_n } else { 0 };
    ctx.set("until", &format!("{until}\n"));
    ctx.set("reason", "ok");
    let token = match new_token(ctx) {
        Ok(t) => t,
        Err(msg) => {
            ctx.unset("until");
            return Err(fail_start(ctx, "stopped", 3, None, &msg));
        }
    };
    if proc::cancelled() {
        ctx.unset("supervisor.token");
        ctx.log("start cancelled before the window opened");
        return Ok(3);
    }
    // Detached in its own session: pkexec tears down its process group when
    // this call returns (22:46:10Z took the responder and the watcher with
    // it), and the window's children must outlive us.
    let mut child = match spawn_supervisor(ctx, until, secs, &token) {
        Ok(c) => c,
        Err(e) => {
            ctx.unset("supervisor.token");
            ctx.unset("until");
            ctx.log(&format!("could not start the supervisor: {e}"));
            return Err(fail_start(
                ctx,
                "stopped",
                3,
                None,
                "supervisor did not start",
            ));
        }
    };
    // Never return 0 for a window that did not come up.
    for _ in 0..10 {
        if supervisor_alive(ctx) {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    if !supervisor_alive(ctx) {
        ctx.unset("supervisor.token");
        let _ = child.kill();
        reap(ctx, "supervisor", child, Instant::now() + REAP);
        kill_children(ctx);
        ctx.unset("until");
        return Err(fail_start(
            ctx,
            "stopped",
            3,
            None,
            "supervisor did not start",
        ));
    }
    if secs_n > 0 {
        ctx.log(&format!("discoverable until {} ({secs}s)", clock(until)));
    } else {
        ctx.log("discoverable until turned off");
    }
    Ok(0)
}

/// 128 random bits in a root-only file. An unprivileged caller can read
/// neither the file nor the supervisor's environment, so a direct
/// `pkexec omdrop-radio __supervise` cannot present it.
fn new_token(ctx: &Ctx) -> Result<String, String> {
    use std::io::Read;
    let mut raw = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut raw))
        .map_err(|_| "could not read /dev/urandom for the supervisor token".to_string())?;
    let token: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    ctx.rd
        .as_ref()
        .ok_or_else(|| "the run directory is not open".to_string())?
        .write("supervisor.token", &token, 0o600)
        .map_err(|_| "could not write the supervisor token".to_string())?;
    Ok(token)
}

fn spawn_supervisor(ctx: &Ctx, until: u64, secs: &str, token: &str) -> std::io::Result<Child> {
    let log = ctx
        .rd
        .as_ref()
        .ok_or_else(|| std::io::Error::other("the run directory is not open"))?
        .append("log")?;
    let mut cmd = Command::new(&ctx.self_exe);
    cmd.args(["__supervise", &until.to_string(), secs])
        .env_clear()
        .envs(ctx.child_env())
        .env("OMDROP_SUPERVISOR_TOKEN", token)
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log));
    // SAFETY: setsid is async-signal-safe and touches no Rust state.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd.spawn()
}

// --- the supervisor ---------------------------------------------------------

/// Only a supervisor that `start` spawned may run: polkit authorizes the
/// program, not its argv, so `pkexec omdrop-radio __supervise ...` reaches
/// this directly and would skip every check `start` makes.
pub fn supervise_entry(ctx: &mut Ctx, args: &[String]) -> Res {
    need_root(ctx, &["__supervise"])?;
    let want = std::env::var("OMDROP_SUPERVISOR_TOKEN").unwrap_or_default();
    // SAFETY: still single-threaded here; nothing else reads the environment.
    unsafe { std::env::remove_var("OMDROP_SUPERVISOR_TOKEN") };
    ctx.mkdir_run()?;
    let got = ctx.state("supervisor.token").unwrap_or_default();
    let valid = want.len() == 32 && want.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if !(valid && same(want.as_bytes(), got.as_bytes())) {
        // A call that cannot present the token leaves the file alone, so it
        // cannot make a real start fail.
        return Err(exit(
            2,
            format!(
                "__supervise is internal; use: {} start <seconds>",
                ctx.self_str()
            ),
        ));
    }
    ctx.unset("supervisor.token");
    let deadline = args.first().map(String::as_str).unwrap_or("");
    if args.len() > 2 || !is_uint(deadline) {
        return Err(exit(2, "__supervise: deadline must be a number"));
    }
    let secs = args.get(1).map(String::as_str).unwrap_or("");
    if !is_duration(secs) {
        return Err(exit(2, "__supervise: seconds must be a number"));
    }
    let secs: u64 = secs
        .parse()
        .map_err(|_| exit(2, "__supervise: seconds must be a number"))?;
    supervise(ctx, secs)
}

fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

enum End {
    Stopped,
    Expired,
    RadioLost,
}

fn supervise(ctx: &mut Ctx, secs: u64) -> Res {
    // Our stderr is the log file already.
    ctx.log_to_stderr = false;
    proc::catch_termination();
    let me = std::process::id();
    let my_start = proc::start_time(me).unwrap_or(0);
    let me_line = format!("{me} {my_start}");
    ctx.set("supervisor", &format!("{me_line}\n"));
    let announce = Announce::parse(ctx.state("announce"));
    let adv = adv(ctx);
    let mut children: Vec<(String, Child)> = Vec::new();
    let mut keep = |tag: &str, c: Option<Child>| {
        if let Some(c) = c {
            children.push((tag.to_string(), c));
        }
    };
    if announce.mdns
        && let Some(adv) = &adv
    {
        let args = [
            "mdns",
            "--iface",
            IFACE,
            "--port",
            RECEIVER_PORT,
            "--flags",
            ADV_FLAGS,
        ]
        .map(String::from);
        keep("mdns", spawn(ctx, "mdns", adv, &args));
    }
    // Peer registration is what makes our SYN-ACKs leave the radio: unicast to
    // a MAC with no firmware peer entry completes FW_TOSSED (074311Z).
    let watch = ctx.paths.hooks.join("peer-watch");
    if watch.exists() {
        match crate::ctx::trusted(&watch, ctx.trusted_owner()) {
            Ok(()) => keep("peers", spawn(ctx, "peers", &watch, &[])),
            Err(e) => ctx.log(&format!("radio hook peer-watch not run: {e}")),
        }
    }
    if ctx.paths.conf.join("ble-wake").exists() {
        // Opt-in: it advertises us as a SENDER on the radio AWDL shares. A day
        // stands in for an unbounded window: --seconds needs a number.
        if let Some(adv) = &adv {
            let s = if secs > 0 { secs } else { 86_400 };
            let args = ["ble", "--arm", "A", "--seconds", &s.to_string()].map(String::from);
            keep("ble", spawn(ctx, "ble", adv, &args));
        }
    }

    let mut seq: u64 = 0;
    // The deadline is re-read every interval: `start` rewrites it when a
    // second press extends the window. A missing or invalid file means the
    // window was torn down underneath us, which is a reason to stop.
    let end = loop {
        if proc::cancelled() {
            break End::Stopped;
        }
        if !until_live(ctx) && end_window(ctx, true) {
            break End::Expired;
        }
        seq = seq.saturating_add(1);
        let o = Opts {
            record: true,
            ..opts(TICK_TIMEOUT)
        };
        match proc::hook(ctx, "tick", &[&seq.to_string()], o).outcome {
            Outcome::Exited(0) | Outcome::Missing => {}
            Outcome::Cancelled => break End::Stopped,
            Outcome::Exited(4) => break End::RadioLost,
            o => ctx.log(&format!("tick: {}", o.describe())),
        }
        rx_watch(ctx);
        if seq % 10 == 1 {
            net::mdns_reclaim(ctx);
        }
        if let Some(adv) = &adv {
            let mut args = vec![
                "announce".to_string(),
                "--iface".into(),
                IFACE.into(),
                "--count".into(),
                announce.count.to_string(),
                "--interval".into(),
                announce.interval_arg(),
                "--flags".into(),
                ADV_FLAGS.into(),
                "--seq".into(),
                seq.saturating_mul(100).to_string(),
            ];
            if announce.plain {
                args.push("--plain".into());
            }
            let burst = Duration::from_micros(announce.count * announce.interval_us)
                + Duration::from_secs(30);
            let o = Opts {
                log_stderr: false,
                record: true,
                ..opts(burst)
            };
            if proc::run(ctx, adv, &args, o).outcome == Outcome::Cancelled {
                break End::Stopped;
            }
        }
        children.retain_mut(|(tag, c)| match c.try_wait() {
            Ok(Some(st)) => {
                ctx.log(&format!("{tag} exited ({st})"));
                false
            }
            _ => true,
        });
        if !proc::sleep(Duration::from_secs(announce.period_s)) {
            break End::Stopped;
        }
    };
    if !matches!(end, End::Expired) {
        // Stopped, or the radio is gone: the window ends whatever `until` says.
        end_window(ctx, false);
    }
    let (reason, why) = match end {
        End::Stopped => ("stopped", None),
        End::Expired => {
            ctx.log("window expired");
            ("expired", Some("expired"))
        }
        End::RadioLost => {
            ctx.log("the radio backend reports the radio gone; ending the window");
            ("no_awdl0", Some("radio-lost"))
        }
    };
    kill_children(ctx);
    // What the pids file did not name (or `stop` already took) is still ours
    // to end: these Child handles are unreaped, so their pids, and with them
    // their process groups, cannot have been reused.
    for (_, c) in &mut children {
        if matches!(c.try_wait(), Ok(None)) {
            proc::signal(-(c.id() as i32), libc::SIGKILL);
        }
    }
    let reap_until = Instant::now() + REAP;
    for (tag, c) in children {
        reap(ctx, &tag, c, reap_until);
    }
    ctx.set("reason", reason);
    // `stop` runs `down` itself once every supervisor is gone.
    if let Some(why) = why {
        down(ctx, why, true);
    }
    if ctx.state("supervisor").as_deref() == Some(me_line.as_str()) {
        ctx.unset("supervisor");
    }
    Ok(0)
}

// --- stop -------------------------------------------------------------------

/// Pidfds for every live process other than us, running as root, for which
/// `pred` holds; re-checked after the open.
fn handles(ctx: &Ctx, pred: impl Fn(u32) -> bool + Clone + 'static) -> Vec<Pidfd> {
    let me = std::process::id();
    let owner = ctx.trusted_owner();
    proc::find(owner, &pred)
        .into_iter()
        .filter(|&p| p != me)
        .filter_map(|p| {
            let pred = pred.clone();
            Pidfd::open(p, move |p| pred(p) && proc::owned_by(p, owner))
        })
        .collect()
}

pub fn stop(ctx: &mut Ctx, args: &[String]) -> Res {
    if !args.is_empty() {
        return Err(crate::usage(ctx));
    }
    need_root(ctx, &["stop"])?;
    ctx.mkdir_run()?;
    // A start still in `up` owns no supervisor yet, but it is toggling the
    // radio: "stop" has to mean that too, or a stuck gate keeps cycling it
    // after the button is off.
    let exe = ctx.self_exe.clone();
    let starts = handles(ctx, move |p| proc::is_invocation(p, &exe, "start"));
    for s in &starts {
        if s.signal(libc::SIGTERM) {
            ctx.log(&format!(
                "cancelled a start still in its gate (pid {})",
                s.pid
            ));
        }
    }
    proc::wait_exited(&starts, Duration::from_secs(5));
    // Every supervisor, not only the recorded one, and 0.9.x's too: leaving
    // either alive keeps rewriting the template after the panel says off.
    let exe = ctx.self_exe.clone();
    let mut sups = handles(ctx, move |p| proc::is_invocation(p, &exe, "__supervise"));
    let legacy = legacy_supervisors(ctx);
    let lexe = legacy_exe(ctx);
    sups.extend(handles(ctx, move |p| {
        legacy.contains(&p) && is_legacy_supervisor(&lexe, p)
    }));
    if let Some(errno) = proc::pidfd_unavailable() {
        ctx.log(&format!(
            "pidfd_open is unavailable (errno {errno}); signalling by pid, re-checking each process first"
        ));
    }
    for s in &sups {
        s.signal(libc::SIGTERM);
    }
    if !proc::wait_exited(&sups, Duration::from_secs(10)) {
        for s in sups.iter().filter(|s| !s.exited()) {
            s.signal(libc::SIGKILL);
        }
        proc::wait_exited(&sups, Duration::from_secs(2));
    }
    kill_orphaned_hook(ctx);
    kill_children(ctx);
    ctx.unset("until");
    ctx.unset("supervisor");
    ctx.unset("supervisor.token");
    down(ctx, "stopped", false);
    ctx.set("reason", "stopped");
    net::mdns_reclaim(ctx);
    ctx.log("stopped");
    Ok(0)
}

// --- status -----------------------------------------------------------------

pub fn status(ctx: &mut Ctx, args: &[String]) -> Res {
    let json = match args {
        [] => false,
        [a] if a == "--json" => true,
        _ => return Err(crate::usage(ctx)),
    };
    ctx.open_run_for_status();
    let until = ctx.state("until").unwrap_or_default();
    let mut reason = ctx.state("reason").unwrap_or_else(|| "stopped".into());
    let rx = ctx.state("rx_proven").as_deref() == Some("1");
    let visible;
    let mut remaining = "null".to_string();
    let live_until =
        is_uint(&until) && (until == "0" || until.parse::<u64>().is_ok_and(|u| now() < u));
    if !net::iface_exists(ctx) || !net::has_link_local(ctx) {
        // Present but without a link-local is unusable: nothing can bind to
        // :8771 and no transfer can land, and reporting ok there sent a peer
        // into three sends against a void (08:26:12Z).
        visible = false;
        reason = "no_awdl0".into();
    } else if live_until && (supervisor_alive(ctx) || !legacy_supervisors(ctx).is_empty()) {
        // Live either way; say whether receive is proven, so a panel can tell
        // "visible" from "advertising, nothing has answered yet".
        visible = true;
        if until != "0" {
            remaining = until
                .parse::<u64>()
                .map(|u| u.saturating_sub(now()).to_string())
                .unwrap_or(remaining);
        }
        reason = if rx { "ok".into() } else { "unproven".into() };
    } else {
        visible = false;
        if reason == "ok" || reason == "unproven" {
            reason = "expired".into();
        }
    }
    // A peer whose firmware entry is missing loses every unicast frame before
    // air: advertising is then true and useless for that device (2026-09-19).
    let degraded = ctx.has("peerop.degraded");
    let peer_op = if degraded { "degraded" } else { "ok" };
    if degraded && reason == "ok" {
        reason = "peer_op_failed".into();
    }
    if json {
        let reason = serde_json::to_string(&reason).unwrap_or_else(|_| "\"\"".into());
        println!(
            "{{\"visible\":{visible},\"remaining\":{remaining},\"reason\":{reason},\"rx_proven\":{rx},\"peer_op\":\"{peer_op}\"}}"
        );
    } else {
        println!(
            "visible={visible} remaining={remaining} reason={reason} rx_proven={rx} peer_op={peer_op}"
        );
        if degraded {
            eprintln!(
                "peer_op ADD is failing: some devices cannot see you and will not receive anything you send.\nClear it with: pkexec /usr/lib/omdrop/awdl-up --reload"
            );
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The backend contract promises callers that `start` returns within
    /// 900 s, and the CLI waits that long (omdrop-cli RADIO_START_LIMIT).
    /// A caller that gives up sooner stops a start that would have worked.
    /// This is the slowest path through `start`: every wait and hook runs
    /// to its bound, and the supervisor then fails to start.
    #[test]
    fn start_returns_within_the_contracts_bound() {
        const CONTRACT_START_BOUND: Duration = Duration::from_secs(900);
        // proc::hook past a timeout: TERM, GRACE, KILL, up to REAP for the
        // exit, then DRAIN for the pipes.
        let killed = |t: Duration| t + proc::GRACE + proc::REAP + proc::DRAIN;
        let kill_children = Duration::from_secs(1) + REAP;
        let worst = WARMUP_HANDOFF
            + WARMUP_WAIT
            + WINDOW_LOCK_WAIT
            + CLOSING_WAIT
            + Duration::from_secs(2) // kill_orphaned_hook
            + kill_children
            + killed(PROBE_TIMEOUT)
            + killed(UP_TIMEOUT)
            + killed(IDENTITY_TIMEOUT)
            + Duration::from_secs(5) // 10 checks 500 ms apart for the supervisor
            + REAP // reaping a supervisor that did not come up
            + kill_children
            + killed(DOWN_TIMEOUT); // fail_start runs `down start-failed`
        let slack = Duration::from_secs(15); // state-file I/O, pipe drains
        assert!(
            worst + slack <= CONTRACT_START_BOUND,
            "start can take {worst:?} (+{slack:?}); raise the contract's bound and omdrop-cli's RADIO_START_LIMIT together"
        );
    }

    #[test]
    fn interval_is_printed_as_argparse_reads_it() {
        let a = |us| {
            Announce {
                interval_us: us,
                ..Announce::default()
            }
            .interval_arg()
        };
        assert_eq!(a(20_000), "0.02");
        assert_eq!(a(16_400), "0.0164");
        assert_eq!(a(1_000_000), "1");
        assert_eq!(a(1_000), "0.001");
    }

    #[test]
    fn announce_state_is_revalidated() {
        let custom = Announce {
            count: 64,
            interval_us: 16_400,
            period_s: 3,
            plain: true,
            mdns: false,
        };
        assert_eq!(Announce::parse(Some(custom.line())), custom);
        assert_eq!(Announce::parse(None), Announce::default());
        for bad in [
            "0 20000 6 0 1",
            "40 20000 6 0",
            "40 020000 6 0 1",
            "40 20000 61 0 1",
            "40 20000 6 2 1",
            "a[$(x)] 1 1 1 1",
        ] {
            assert_eq!(
                Announce::parse(Some(bad.into())),
                Announce::default(),
                "{bad}"
            );
        }
    }

    #[test]
    fn pids_lines_are_parsed_strictly() {
        let l = parse_pids("12 mdns 345\n0 bad\n1 init\n013 octal\nx y\n77 peers\n");
        let got: Vec<_> = l.iter().map(|r| (r.pid, r.tag.as_str(), r.start)).collect();
        assert_eq!(got, vec![(12, "mdns", Some(345)), (77, "peers", None)]);
    }

    #[test]
    fn pid_and_start_time_records() {
        assert_eq!(parse_pid_start("123 456"), Some((123, 456)));
        for bad in ["123", "123 456 7", "0123 456", "1 5", "a 1", "123 -4", ""] {
            assert_eq!(parse_pid_start(bad), None, "{bad}");
        }
    }
}
