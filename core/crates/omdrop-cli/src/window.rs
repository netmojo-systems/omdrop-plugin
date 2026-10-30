//! Receiving on and off, and the first-run setup they depend on.
//!
//! This wraps what already exists rather than inventing state: receiving
//! on/off is airdrop-receiver.service, the window is a transient systemd
//! timer that stops it, and the window's shape is in the watcher's arguments.

use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::config::{cfg_get, cfg_set, default_name, effective_name, setting_get, setting_set};
use crate::ctx::{DEFAULT_WINDOW, ID_EXPIRY, UNIT, WATCH, WINDOW, ctx};
use crate::driver::{awdl_link_local, prereqs_missing};
use crate::identity::{
    Migrated, Out, ensure_tls, id, identity_lock, identity_notice, migrate_identity,
};
use crate::proc::{
    LineReader, Read1, caught, code_of, pipe, run, run_quiet, spinner_restore_tty, spinner_start,
    trap_signals, untrap_signals,
};
use crate::status::{have_unit, receiving};
use crate::util::{die, glob_match, home, is_executable, lexists};

/// First use installs what `setup` would. The panel's switch is the first
/// thing most people press, and "Run: omdrop setup" named a command that
/// only `setup` itself puts on PATH (issue 12).
pub fn require_unit() {
    if have_unit() {
        return;
    }
    setup_install();
    if !have_unit() {
        die("The service that receives files could not be installed. The reason is above.");
    }
}

pub fn cancel_window() {
    for unit in [
        format!("{WINDOW}.timer"),
        format!("{WATCH}.service"),
        format!("{ID_EXPIRY}.timer"),
    ] {
        run_quiet("systemctl", &["--user", "stop", &unit]);
    }
    // A transient unit that failed stays loaded under its name, and the next
    // `systemd-run --unit=` of that name is refused: "the window could not
    // be armed" ever after.
    run_quiet(
        "systemctl",
        &[
            "--user",
            "reset-failed",
            &format!("{WINDOW}.timer"),
            &format!("{WINDOW}.service"),
            &format!("{WATCH}.service"),
            &format!("{ID_EXPIRY}.timer"),
            &format!("{ID_EXPIRY}.service"),
        ],
    );
}

/// A duration as whole seconds, or `None` when it is not one. The check is
/// the bash's, `^[0-9]+(s|sec|m|min|h|hour|d|day)?$`, and a bare number
/// means MINUTES: systemd reads it as seconds, so `on 3` opened a
/// three-second window that was over before anyone read the line saying so.
/// Returns the span as systemd should be given it, and its seconds.
pub fn parse_duration(dur: &str) -> Result<(String, u64), String> {
    let split = dur.find(|c: char| !c.is_ascii_digit()).unwrap_or(dur.len());
    let (digits, unit) = dur.split_at(split);
    let mult: u64 = match unit {
        "" | "m" | "min" => 60,
        "s" | "sec" => 1,
        "h" | "hour" => 3600,
        "d" | "day" => 86_400,
        _ => 0,
    };
    if digits.is_empty() || mult == 0 {
        return Err(format!(
            "duration {dur}: a systemd time span such as 10m or 1h, or \"once\" or \"forever\""
        ));
    }
    let span = if unit.is_empty() {
        format!("{dur}m")
    } else {
        dur.to_string()
    };
    let secs = digits
        .trim_start_matches('0')
        .parse::<u64>()
        .or_else(|e| {
            if digits.bytes().all(|b| b == b'0') {
                Ok(0)
            } else {
                Err(e)
            }
        })
        .ok()
        .and_then(|n| n.checked_mul(mult))
        // systemd keeps spans in microseconds and reserves the top value.
        .filter(|s| s.checked_mul(1_000_000).is_some_and(|us| us < u64::MAX))
        .ok_or_else(|| format!("duration {span}: could not read that as a time span"))?;
    Ok((span, secs))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Timed,
    Forever,
    Once,
}

pub fn cmd_on(args: &[String]) -> i32 {
    require_unit();
    let c = ctx();

    // -c/--contacts and -e/--everyone SET the saved visibility rather than
    // applying for one window: the receiver reads it per request, and a mode
    // that silently reverted would be a privacy setting nobody could rely on.
    let mut want_vis = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-c" | "--contacts" => want_vis = Some("contacts"),
            "-e" | "--everyone" => want_vis = Some("everyone"),
            "--" => {
                i += 1;
                break;
            }
            a if a.starts_with('-') => die(format!(
                "omdrop on: unknown option {a}. Use -c/--contacts or -e/--everyone."
            )),
            _ => break,
        }
        i += 1;
    }
    let rest = &args[i..];
    if rest.len() > 1 {
        die(format!(
            "omdrop on: one duration at a time, not \"{}\"",
            rest.join(" ")
        ));
    }

    // Checked before anything is armed: a typo must not leave us visible
    // with no window when a window is exactly what was asked for.
    let dur_arg = rest
        .first()
        .filter(|d| !d.is_empty())
        .map(String::as_str)
        .unwrap_or(DEFAULT_WINDOW);
    let (mut mode, mut dur, mut secs) = (Mode::Timed, String::new(), None::<u64>);
    match dur_arg {
        "forever" => mode = Mode::Forever,
        "once" => mode = Mode::Once,
        d => {
            let (span, s) = parse_duration(d).unwrap_or_else(|e| die(e));
            // Zero is one-shot, which is how the panel's slider spells its floor.
            if s == 0 {
                mode = Mode::Once;
            } else {
                dur = span;
                secs = Some(s);
            }
        }
    }

    if let Some(v) = want_vis {
        crate::proc::with_stdout_null(|| crate::status::cmd_visibility(&[v.to_string()]));
    }

    // The identity is settled before anything starts, so a cancelled start
    // has nothing to undo. `begin` makes sure the self-signed pair exists
    // and fetches from 1Password when needed -- the one step without the
    // lock, so `off` can interrupt it. Then, under the lock, `window`
    // refuses if an `off` ran meanwhile, and otherwise fixes this window's
    // identity; the lock is held until the receiver and radio are up.
    let name = effective_name();
    let begun = id(&["begin", "--name", &name], Out::Capture, true);
    if begun.code != 0 {
        die("The AirDrop receiver would not start: this computer's identity is unusable.");
    }
    let mut seq = String::new();
    for line in begun.stdout.lines() {
        if let Some(v) = line.strip_prefix("seq=") {
            seq = v.to_string();
        } else if let Some(v) = line.strip_prefix("notice=") {
            identity_notice(v);
        }
    }
    let lock = identity_lock();
    let win = id(&["window", "--seq", &seq], Out::Capture, true);
    if win.code == 3 {
        drop(lock);
        errln!("Omdrop was turned off while it was starting.");
        return 0;
    }
    if win.code != 0 {
        die("The AirDrop receiver would not start: its identity could not be settled.");
    }
    let (mut source, mut expiry) = (String::new(), None::<String>);
    for line in win.stdout.lines() {
        if let Some(v) = line.strip_prefix("source=") {
            source = v.to_string();
        } else if let Some(v) = line.strip_prefix("expiry_in=") {
            expiry = Some(v.to_string());
        } else if let Some(v) = line.strip_prefix("notice=") {
            identity_notice(v);
        }
    }
    // Every way out of a failed start clears what `window` set up.
    let identity_abort = || {
        id(&["stop-begin"], Out::Null, false);
        id(&["stop-end"], Out::Null, false);
    };

    cancel_window();
    let self_exe = c.command_path().to_string_lossy().into_owned();

    // The 1Password cache's hard expiry is absolute: a window still open then
    // is turned off, because a kernel timeout cannot reach a key the receiver
    // has already loaded. A window that cannot arm it does not start.
    if let Some(exp) = expiry.filter(|e| source == "1password" && !e.is_empty()) {
        let n = exp.trim().parse::<i64>().unwrap_or(0);
        let on_active = format!("--on-active={}s", if n > 0 { n } else { 1 });
        let unit = format!("--unit={ID_EXPIRY}");
        if run(
            "systemd-run",
            &[
                "--user", "--quiet", &on_active, &unit, &self_exe, "off", "--force",
            ],
        ) != 0
        {
            identity_abort();
            die(
                "The AirDrop receiver would not start: the identity cache's expiry could not be armed.",
            );
        }
    }

    // The watcher goes up BEFORE the radio, carrying the window's shape,
    // because `status` reads the mode off it: otherwise the panel's duration
    // row read "Until I turn it off" for the whole radio gate (2026-09-18).
    // The deadline is NOT armed here: a clock started before the radio is up
    // spends the gate counting down a window nobody can send to.
    let unit = format!("--unit={WATCH}");
    let mut watch: Vec<&str> = vec!["--user", "--quiet", &unit, &self_exe, "watch"];
    match mode {
        Mode::Once => watch.push("--once"),
        Mode::Timed => watch.extend(["--window", dur.as_str()]),
        Mode::Forever => {}
    }
    if run("systemd-run", &watch) != 0 {
        errln!("receiving, but nothing is watching for arrivals");
    }

    // Receiver FIRST when it can start, radio second: a window once
    // advertised 16 s before the receiver listened, and 45 SYNs were answered
    // by nothing. But a cold awdl0 has no link-local until AWDL is up, and the
    // receiver refuses to start without one, so then the radio goes first.
    let radio_secs = secs.unwrap_or(0).to_string();
    let helper = is_executable(&c.discoverable);
    let radio_stop = || {
        if helper {
            run_quiet("pkexec", &[c.discoverable.as_os_str(), "stop".as_ref()]);
        }
    };
    let radio_failed = |err: String| -> ! {
        die(if err.is_empty() {
            "The AirDrop radio could not be started.".to_string()
        } else {
            err
        })
    };
    // A start cancelled while the radio comes up is undone like a failed
    // one before saying "Cancelled.": the bash died there and left the
    // receiver up with no window (deliberately different).
    let undo_and_cancel = |receiver_up: bool| -> ! {
        cancel_window();
        if receiver_up {
            run_quiet("systemctl", &["--user", "stop", UNIT]);
        }
        radio_stop();
        identity_abort();
        crate::proc::cancelled(None)
    };
    if awdl_link_local() {
        if !start_receiver() {
            cancel_window();
            identity_abort();
            die("The AirDrop receiver would not start.");
        }
        match radio_up(&radio_secs) {
            Radio::Up => {}
            Radio::Cancelled => undo_and_cancel(true),
            Radio::Failed(err) => {
                cancel_window();
                run_quiet("systemctl", &["--user", "stop", UNIT]);
                radio_stop();
                identity_abort();
                radio_failed(err);
            }
        }
    } else {
        match radio_up(&radio_secs) {
            Radio::Up => {}
            Radio::Cancelled => undo_and_cancel(false),
            Radio::Failed(err) => {
                cancel_window();
                // A start that timed out may still finish; stopping a radio
                // that is not up costs nothing.
                radio_stop();
                identity_abort();
                radio_failed(err);
            }
        }
        if !start_receiver() {
            cancel_window();
            radio_stop();
            identity_abort();
            die("The AirDrop receiver would not start.");
        }
    }

    // Receiving works from here, so this is where the clock starts. The
    // radio's own deadline began with the gate, so ask it for the window
    // again so both ends agree on when this closes.
    if mode == Mode::Timed {
        let on_active = format!("--on-active={dur}");
        let unit = format!("--unit={WINDOW}");
        if run(
            "systemd-run",
            &[
                "--user", "--quiet", &on_active, &unit, &self_exe, "off", "--force",
            ],
        ) != 0
        {
            die(format!(
                "receiving, but the {dur} window could not be armed -- turn it off yourself"
            ));
        }
        if helper {
            run_quiet(
                "pkexec",
                &[
                    c.discoverable.as_os_str(),
                    "start".as_ref(),
                    radio_secs.as_ref(),
                ],
            );
        }
    }
    drop(lock);
    crate::status::cmd_status(&[])
}

/// How long `pkexec HELPER start` may take: the backend contract's bound on
/// `start` (docs/backend-contract.md), which omdrop-radio's
/// `start_returns_within_the_contracts_bound` test checks against its own
/// waits and hook timeouts. Giving up sooner would stop a start that was
/// going to work, such as one waiting for a closing window and then a slow
/// `up`. The identity lock is held meanwhile, so without a bound a hung
/// helper would hang every `off` too.
pub const RADIO_START_LIMIT: Duration = Duration::from_secs(900);

enum Radio {
    Up,
    Failed(String),
    Cancelled,
}

/// The radio half: AWDL announcements and the BLE wake advert. On failure,
/// what it said, so the panel can show a reason: the helper timestamps every
/// line and ends with the failure, so keep that line minus the timestamp.
/// TERM, INT or HUP meanwhile is `Cancelled`, for the caller to undo the
/// start before exiting.
fn radio_up(secs: &str) -> Radio {
    let limit = RADIO_START_LIMIT;
    let d = &ctx().discoverable;
    if !is_executable(d) {
        return Radio::Up;
    }
    // Bringing the radio up takes seven or eight seconds, so it gets the
    // spinner -- but only when the grant is passwordless: a spinner erasing
    // the line every 100 ms would stamp on pkexec's password prompt.
    // --disable-internal-agent makes the probe fail instead of prompting.
    let passwordless = run_quiet(
        "pkexec",
        &[
            "--disable-internal-agent".as_ref(),
            d.as_os_str(),
            "status".as_ref(),
        ],
    ) == 0;
    let Ok((read, write)) = pipe() else {
        return Radio::Failed(String::new());
    };
    let mut cmd = Command::new("pkexec");
    cmd.arg(d)
        .args(["start", secs])
        .stdout(Stdio::null())
        .stderr(Stdio::from(write));
    // Its own process group when nothing has to be typed, so the deadline
    // can take down all of it; a password prompt needs the terminal's group.
    if passwordless {
        cmd.process_group(0);
    }
    trap_signals();
    let child = cmd.spawn();
    drop(cmd);
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            untrap_signals();
            return Radio::Failed(format!("omdrop: pkexec: {e}"));
        }
    };
    if passwordless {
        spinner_start("waking the radio");
    }
    let deadline = Instant::now() + limit;
    let mut reader = LineReader::new(read);
    let mut out = String::new();
    let mut outcome = None;
    loop {
        match reader.read_line(Some(deadline)) {
            Read1::Line(l) => {
                out.push_str(&String::from_utf8_lossy(&l));
                out.push('\n');
            }
            Read1::Eof => break,
            Read1::Signal => {
                outcome = Some(Radio::Cancelled);
                break;
            }
            Read1::Timeout => {
                outcome = Some(timed_out(limit));
                break;
            }
        }
    }
    let rc = match outcome {
        Some(_) => None,
        None => loop {
            match child.try_wait() {
                Ok(Some(s)) => break Some(code_of(s)),
                Ok(None) => {}
                Err(_) => break Some(1),
            }
            if caught().is_some() {
                outcome = Some(Radio::Cancelled);
                break None;
            }
            if Instant::now() >= deadline {
                outcome = Some(timed_out(limit));
                break None;
            }
            std::thread::sleep(Duration::from_millis(20));
        },
    };
    spinner_restore_tty();
    if rc.is_none() {
        // Best effort: once pkexec has become the root helper it cannot be
        // signalled from here, and the caller's `stop` is what ends it.
        abandon(&mut child, passwordless);
    }
    match outcome {
        Some(Radio::Cancelled) => return Radio::Cancelled,
        Some(other) => {
            untrap_signals();
            return other;
        }
        None => {}
    }
    if caught().is_some() {
        return Radio::Cancelled;
    }
    untrap_signals();
    // 5 is "already starting or already visible": a race with a window that
    // is already coming up, not a refusal.
    match rc {
        Some(0 | 5) => Radio::Up,
        _ => Radio::Failed(last_radio_line(&out)),
    }
}

fn timed_out(limit: Duration) -> Radio {
    Radio::Failed(format!(
        "The AirDrop radio did not come up within {} seconds.",
        limit.as_secs()
    ))
}

fn abandon(child: &mut std::process::Child, own_group: bool) {
    let Ok(pid) = i32::try_from(child.id()) else {
        return;
    };
    let target = if own_group { -pid } else { pid };
    // SAFETY: signalling our own child, or the group it leads.
    unsafe { libc::kill(target, libc::SIGTERM) };
    for _ in 0..20 {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // Only while the leader is unreaped is the id certainly still its group's.
    if matches!(child.try_wait(), Ok(None)) {
        // SAFETY: as above.
        unsafe { libc::kill(target, libc::SIGKILL) };
        let _ = child.try_wait();
    }
}

pub fn last_radio_line(out: &str) -> String {
    let last = out.lines().rfind(|l| !l.trim().is_empty()).unwrap_or("");
    let b = last.as_bytes();
    let stamped = b.len() > 9
        && b[..9].iter().enumerate().all(|(i, &c)| match i {
            2 | 5 => c == b':',
            8 => c == b'Z',
            _ => c.is_ascii_digit(),
        })
        && b[9] == b' ';
    if stamped {
        last[10..].to_string()
    } else {
        last.to_string()
    }
}

/// systemd latches a unit that failed too often, and every later start is
/// refused with no attempt made -- the morning after a receiver could not
/// rebind 8771. Clearing the latch costs nothing. The unit and identity are
/// brought up to date first, so a plugin update needs no separate setup.
fn start_receiver() -> bool {
    let c = ctx();
    let Some(plugin) = c.plugin_dir() else {
        errln!("omdrop cannot tell where it is installed.");
        return false;
    };
    unit_install(plugin);
    if !crate::identity::prepare_identity() {
        return false;
    }
    if ensure_tls() == 2 {
        return false;
    }
    // The unit may write opt-in protocol dumps only here, and its sandbox
    // cannot create the directory.
    let _ = crate::util::mkdir_private(&c.state_dir().join("debug"));
    run_quiet("systemctl", &["--user", "reset-failed", UNIT]);
    run("systemctl", &["--user", "start", UNIT]) == 0
}

/// Sends in progress, one marker per `omdrop send` process naming where it
/// is going. Turning Omdrop off mid-send cuts the transfer, and the other end
/// never hears it end: a Mac kept a 0-byte file "in use" and stopped
/// accepting connections from this machine (2026-10-09).
pub fn sends_dir() -> PathBuf {
    ctx().state_dir().join("sends")
}

pub fn mark_sending(to: &str) {
    let dir = sends_dir();
    let marker = dir.join(std::process::id().to_string());
    if crate::util::mkdir_private(&dir).is_ok()
        && std::fs::write(&marker, format!("{to}\n")).is_ok()
    {
        crate::util::remove_at_exit(marker);
    }
}

/// Where the live sends are going. A marker whose process has gone (killed,
/// crashed) is cleared rather than believed.
pub fn sending_to(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<_> = entries.flatten().map(|e| e.file_name()).collect();
    names.sort();
    let mut out = Vec::new();
    for name in names {
        let path = dir.join(&name);
        let s = name.to_string_lossy();
        if s.starts_with('.') {
            continue;
        }
        let alive = !s.is_empty()
            && s.bytes().all(|b| b.is_ascii_digit())
            // SAFETY: signal 0 only checks that the process exists.
            && s.parse::<i32>().is_ok_and(|pid| pid > 0 && unsafe { libc::kill(pid, 0) } == 0);
        if alive {
            if let Ok(text) = std::fs::read(&path) {
                out.extend(String::from_utf8_lossy(&text).lines().map(str::to_string));
            }
        } else {
            let _ = std::fs::remove_file(&path);
        }
    }
    out
}

pub fn cmd_off(args: &[String]) -> i32 {
    let force = match args.first().map(String::as_str) {
        Some("--force") => true,
        None | Some("") => false,
        Some(other) => die(format!("off: no such option {other}")),
    };
    require_unit();
    // A person asking for off while a send is running gets told, not
    // obeyed. The timers that close a window pass --force: nobody is there.
    if !force && let Some(to) = sending_to(&sends_dir()).into_iter().next() {
        die(format!(
            "Still sending to {to}. Turning Omdrop off now would cut the transfer off. Cancel the send first, or turn it off anyway with: omdrop off --force"
        ));
    }
    off_under_lock();
    crate::status::cmd_status(&[])
}

/// Under the identity lock, in this order: nothing that starts later can
/// publish into this window; the receiver stops before the identity it
/// loaded is released; the window file goes last.
fn off_under_lock() {
    let c = ctx();
    let lock = identity_lock();
    id(&["stop-begin"], Out::Inherit, true);
    if run("systemctl", &["--user", "stop", UNIT]) != 0 {
        die("The AirDrop receiver would not stop.");
    }
    cancel_window();
    // Stop advertising even if the receiver was already down: the two can
    // drift apart when something else stopped one of them.
    if is_executable(&c.discoverable) {
        run_quiet("pkexec", &[c.discoverable.as_os_str(), "stop".as_ref()]);
    }
    id(&["stop-end"], Out::Inherit, true);
    drop(lock);
}

pub fn cmd_toggle(args: &[String]) -> i32 {
    require_unit();
    if receiving() {
        cmd_off(&[])
    } else {
        cmd_on(&[args.first().cloned().unwrap_or_default()])
    }
}

/// The receiver's unit, from the plugin's template: `@PLUGIN_DIR@` filled
/// in, and the core receiver in ExecStart when it is installed. The options
/// stay the template's, which are airdrop-serve.py's. In ExecStart a word
/// holding the plugin directory is quoted as one word; elsewhere only `%` is
/// escaped, so systemd does not read it as a specifier. `None` when a path
/// holds a line break, which would add lines of its own to the unit.
pub fn render_unit(template: &str, plugin: &Path, receiver: Option<&Path>) -> Option<String> {
    const PLACEHOLDER: &str = "@PLUGIN_DIR@";
    let plugin_s = plugin.to_string_lossy();
    if plugin_s.chars().any(char::is_control) {
        return None;
    }
    let marker = format!("{PLACEHOLDER}/bin/airdrop-serve.py");
    let mut lines = Vec::new();
    for line in template.split('\n') {
        let rendered = match line.strip_prefix("ExecStart=") {
            Some(cmd) => match (receiver, cmd.find(&marker)) {
                (Some(rx), Some(at)) => format!(
                    "ExecStart={}{}",
                    systemd_quote(&rx.to_string_lossy())?,
                    &cmd[at + marker.len()..]
                ),
                _ => {
                    let words: Option<Vec<String>> = cmd
                        .split(' ')
                        .map(|w| {
                            if w.contains(PLACEHOLDER) {
                                systemd_quote(&w.replace(PLACEHOLDER, &plugin_s))
                            } else {
                                Some(w.to_string())
                            }
                        })
                        .collect();
                    format!("ExecStart={}", words?.join(" "))
                }
            },
            None => line.replace(PLACEHOLDER, &plugin_s.replace('%', "%%")),
        };
        lines.push(rendered);
    }
    Some(lines.join("\n"))
}

/// A path as one systemd word, for ExecStart= and ReadWritePaths=: `%` and
/// `$` doubled, and quoted when it holds a space or a quote. `None` for a
/// path with a line break or another control character.
pub fn systemd_quote(s: &str) -> Option<String> {
    if s.chars().any(char::is_control) {
        return None;
    }
    let escaped = s.replace('%', "%%").replace('$', "$$");
    Some(if escaped.contains([' ', '"', '\'', '\\', ';']) {
        format!("\"{}\"", escaped.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        escaped
    })
}

/// Write the receiving service when the installed copy differs from the
/// template. Run by setup and before every start, so an updated plugin never
/// runs its receiver under the previous version's unit: 0.9.1 moved the
/// identity to ~/.omdrop, and a unit that only allowed writes to ~/.opendrop
/// failed every Discover. True when it wrote something.
pub fn unit_install(plugin: &Path) -> bool {
    let c = ctx();
    let template = plugin.join("share").join(UNIT);
    if !crate::util::is_readable(&template) {
        die(
            "This copy of omdrop is missing the file that describes the receiving service, so there is nothing to set up. Install the plugin again.",
        );
    }
    if c.receiver.is_none() && !crate::util::is_readable(&plugin.join("bin/airdrop-serve.py")) {
        die(
            "This copy of omdrop is missing the program that receives files. Install the plugin again.",
        );
    }
    let raw = std::fs::read_to_string(&template)
        .unwrap_or_else(|_| die("omdrop could not read its own files."));
    let rendered = render_unit(
        crate::util::strip_trailing_newlines(&raw),
        plugin,
        c.receiver.as_deref(),
    )
    .unwrap_or_else(|| {
        die("omdrop is installed under a path with a line break in it, so the receiving service was left alone.")
    });
    // A unit with the placeholder still in it starts nothing, and it would
    // fail at the worst moment -- when someone is trying to send a file.
    if rendered.contains("@PLUGIN_DIR@") {
        die(
            "omdrop could not work out where it is installed, so the receiving service was left alone.",
        );
    }
    let target = c.config_home.join("systemd/user").join(UNIT);
    if let Some(dir) = target.parent()
        && std::fs::create_dir_all(dir).is_err()
    {
        die("omdrop could not create the folder systemd keeps your own services in.");
    }
    let mut changed = false;
    let installed = crate::util::read_trimmed(&target).unwrap_or_default();
    if rendered != installed {
        if std::fs::write(&target, format!("{rendered}\n")).is_err() {
            die("omdrop could not write the receiving service.");
        }
        changed = true;
    }
    // `omdrop dir` drop-ins written before 0.9.1 name the old identity folder.
    let dropin = PathBuf::from(format!("{}.d/10-download-dir.conf", target.display()));
    if let Ok(text) = std::fs::read_to_string(&dropin)
        && text.lines().any(|l| l == "ReadWritePaths=%h/.opendrop")
    {
        let fixed: String = text
            .split_inclusive('\n')
            .map(|l| {
                if l.trim_end_matches('\n') == "ReadWritePaths=%h/.opendrop" {
                    l.replacen("%h/.opendrop", "%h/.omdrop", 1)
                } else {
                    l.to_string()
                }
            })
            .collect();
        if std::fs::write(&dropin, fixed).is_err() {
            die(format!("omdrop could not update {}.", dropin.display()));
        }
        changed = true;
    }
    if changed && run("systemctl", &["--user", "daemon-reload"]) != 0 {
        die(
            "The receiving service was written, but systemd would not reload it. Log out and back in, then try again.",
        );
    }
    changed
}

/// Everything `setup` installs, each step idempotent. True when it changed
/// something. Shared with require_unit, so the first `omdrop on` sets up a
/// fresh install without being asked.
pub fn setup_install() -> bool {
    let c = ctx();
    let plugin = c
        .plugin_dir()
        .unwrap_or_else(|| {
            die("omdrop cannot tell where it is installed, so it did not change anything.")
        })
        .to_path_buf();
    let mut did = false;
    if unit_install(&plugin) {
        did = true;
        outln!("Set up the service that receives files.");
    }
    // A packaged copy has /usr/bin/omdrop. An existing ~/.local/bin/omdrop
    // names the plugin's path under ~/.config, so it follows the copy
    // link_plugin puts there, and keeps following the old one if the user
    // declines.
    if !plugin_packaged(&plugin) && link_command() {
        did = true;
    }
    if link_plugin(&plugin) {
        did = true;
    }
    if add_widget(&plugin) {
        did = true;
    }
    // Received links are stored as .url files, and a Mac may send a .webloc.
    if crate::links::links_install(c.command_path()) {
        did = true;
    }
    // The agent skill is not installed here: it puts instructions into other
    // programs' configuration, so only `omdrop skill install` writes it
    // (plugin 0.16.1, #45). `setup` points at that command.
    if cfg_get("name").is_empty() {
        if !cfg_set("name", &default_name()) {
            die("omdrop could not save the name Apple devices will see.");
        }
        did = true;
        outln!(
            "Apple devices will see this computer as \"{}\". Change it with: omdrop name",
            effective_name()
        );
    }
    // A failed copy must not be followed by a fresh certificate: that would
    // create ~/.omdrop, the copy would never be tried again, and an Apple ID
    // identity in ~/.opendrop would be silently replaced by a self-signed one.
    let migrated = migrate_identity();
    match migrated {
        Migrated::Copied => {
            did = true;
            outln!("{}", crate::identity::copied_message());
        }
        Migrated::Failed => errln!("{}", crate::identity::copy_failed_message()),
        Migrated::Nothing => {}
    }
    if migrated != Migrated::Failed {
        match ensure_tls() {
            0 => {
                did = true;
                outln!("Created the certificate this computer identifies itself with.");
            }
            2 => errln!(
                "The certificate this computer identifies itself with could not be created in {}/keys; the reason is above.",
                crate::identity::identity_dir().display()
            ),
            _ => {}
        }
    }
    did
}

/// Put `omdrop` on the user's PATH as a link to the plugin's `bin/omdrop`,
/// the one entry point: the plugin manifest cannot declare a command, and
/// core's own `omdrop` is off PATH, so the link never points at core. A user
/// who put their own omdrop there outranks us; only a link into a plugin
/// directory, or a dangling one, is replaced. Without a plugin nothing is
/// linked.
fn link_command() -> bool {
    let c = ctx();
    let Some(plugin) = c.plugin() else {
        return false;
    };
    let target = plugin.dir.join("bin/omdrop");
    let bindir = crate::util::env_nonempty("XDG_BIN_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("{}/.local/bin", home())));
    let link = bindir.join("omdrop");
    let current = if lexists(&link) {
        readlink_f(&link).unwrap_or_default()
    } else {
        String::new()
    };
    let target_s = target.to_string_lossy().into_owned();
    if current.is_empty() || glob_match("*/plugins/*/bin/omdrop", &current) {
        let made = std::fs::create_dir_all(&bindir).and_then(|()| {
            if lexists(&link) {
                std::fs::remove_file(&link)?;
            }
            std::os::unix::fs::symlink(&target, &link)
        });
        match made {
            Ok(()) if current != target_s => {
                outln!("Put the omdrop command on your PATH at {}.", link.display());
                return true;
            }
            Ok(()) => {}
            Err(_) => errln!(
                "omdrop could not create {}, so the omdrop command is not on your PATH. Create it by hand: ln -s {target_s} {}",
                link.display(),
                link.display()
            ),
        }
    } else if current != target_s {
        errln!(
            "Left {} alone: it is not ours and points at {current}.",
            link.display()
        );
    }
    false
}

/// Whether this plugin is the omdrop package's copy: one under /usr, or
/// under OMDROP_PACKAGE_ROOT for tests.
fn plugin_packaged(plugin: &Path) -> bool {
    let real = std::fs::canonicalize(plugin).unwrap_or_else(|_| plugin.to_path_buf());
    let root = crate::util::env_nonempty("OMDROP_PACKAGE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/usr"));
    let root = std::fs::canonicalize(&root).unwrap_or(root);
    real.starts_with(&root) && real != root
}

/// Link a packaged plugin (the omdrop package's /usr/share/omdrop) into
/// ~/.config/omarchy/plugins, the only place the shell loads third-party
/// plugins from, and which a package cannot write to. Only a copy under /usr
/// does this: setup run from a development checkout never touches the user's
/// installed plugin.
///
/// A previous installation (a git or marketplace clone, or a link to another
/// copy) is replaced only after the user agrees, which needs a terminal; the
/// panel's first `omdrop on` runs setup without one, so it is left in place
/// with a warning. A replaced clone is moved aside to a hidden directory,
/// which the shell ignores, not deleted. Same as the plugin's bash.
/// OMDROP_PACKAGE_ROOT moves /usr for tests; it only decides whether setup
/// links the plugin into the user's own home, so it grants nothing.
fn link_plugin(plugin: &Path) -> bool {
    use std::io::{BufRead, IsTerminal, Write};
    if !plugin_packaged(plugin) {
        return false;
    }
    let real = std::fs::canonicalize(plugin).unwrap_or_else(|_| plugin.to_path_buf());
    let dir = PathBuf::from(format!("{}/.config/omarchy/plugins", home()));
    let target = dir.join(crate::ctx::PLUGIN_ID);
    let real_s = real.to_string_lossy().into_owned();
    let is_link = std::fs::symlink_metadata(&target).is_ok_and(|m| m.file_type().is_symlink());
    if is_link && readlink_f(&target).as_deref() == Some(real_s.as_str()) {
        return false;
    }
    if is_link && !target.exists() {
        let _ = std::fs::remove_file(&target);
    } else if lexists(&target) {
        let old = readlink_f(&target).unwrap_or_else(|| target.to_string_lossy().into_owned());
        if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
            errln!(
                "A previous Omdrop plugin installation is at {old}, so the shell still runs it rather than the omdrop package. Run omdrop setup in a terminal to replace it."
            );
            return false;
        }
        let have = manifest_version(&target);
        let want = manifest_version(&real);
        let with = match (&have, &want) {
            (Some(h), Some(w)) if crate::driver::version_lt(h, w) => {
                format!("with a newer version ({h} → {w})")
            }
            _ => format!(
                "with version {} (installed: {})",
                want.as_deref().unwrap_or("unknown"),
                have.as_deref().unwrap_or("unknown")
            ),
        };
        print!(
            "Previous Omdrop plugin installation detected at {old}. This package will replace it {with}. Continue? (Y/n) "
        );
        let _ = std::io::stdout().flush();
        let mut answer = String::new();
        // End of input (Ctrl-D) is No; an empty line is Yes.
        if !matches!(std::io::stdin().lock().read_line(&mut answer), Ok(n) if n > 0) {
            answer = "n".into();
        }
        if !matches!(
            answer.trim().to_ascii_lowercase().as_str(),
            "" | "y" | "yes"
        ) {
            outln!("Left {old} in place: the shell keeps running it, not the omdrop package.");
            return false;
        }
        if is_link {
            if std::fs::remove_file(&target).is_err() {
                errln!("omdrop could not remove the link {}.", target.display());
                return false;
            }
        } else {
            let (_, stamp) = crate::proc::capture("date", &["+%Y%m%d-%H%M%S"]);
            let stamp = String::from_utf8_lossy(&stamp).trim().to_string();
            let aside = dir.join(format!(".{}.replaced-{stamp}", crate::ctx::PLUGIN_ID));
            if std::fs::rename(&target, &aside).is_err() {
                errln!(
                    "omdrop could not move {} aside, so it left it in place.",
                    target.display()
                );
                return false;
            }
            outln!(
                "Moved the previous installation to {}. Delete it once Omdrop works from the package.",
                aside.display()
            );
        }
    }
    let made =
        std::fs::create_dir_all(&dir).and_then(|()| std::os::unix::fs::symlink(&real, &target));
    if made.is_err() {
        errln!(
            "omdrop could not link {} to {real_s}, so the bar has no Omdrop widget. Create the link by hand: ln -s {real_s} {}",
            target.display(),
            target.display()
        );
        return false;
    }
    outln!(
        "Added Omdrop to the shell's plugins: {} links to {real_s}.",
        target.display()
    );
    run_quiet("omarchy-shell", &["shell", "rescanPlugins"]);
    true
}

/// Add the packaged plugin's widget to the bar, once. Kept apart from the
/// link, so a failed `omarchy plugin enable` is retried by the next setup,
/// and remembered once it worked, so a user who later removes the widget
/// keeps it removed. Same as the plugin's bash.
fn add_widget(plugin: &Path) -> bool {
    let real = std::fs::canonicalize(plugin).unwrap_or_else(|_| plugin.to_path_buf());
    let target =
        PathBuf::from(format!("{}/.config/omarchy/plugins", home())).join(crate::ctx::PLUGIN_ID);
    let linked = std::fs::symlink_metadata(&target).is_ok_and(|m| m.file_type().is_symlink())
        && readlink_f(&target).as_deref() == Some(&*real.to_string_lossy());
    if !linked || setting_get("widget_added") == "1" {
        return false;
    }
    if run_quiet("omarchy-plugin-enable", &[crate::ctx::PLUGIN_ID]) == 0 {
        setting_set("widget_added", "1");
        outln!("Added its widget to the bar.");
        return true;
    }
    errln!(
        "omdrop could not add its widget to the bar. The next omdrop setup tries again, or run: omarchy plugin enable {}",
        crate::ctx::PLUGIN_ID
    );
    false
}

/// The version a plugin directory's manifest.json declares.
fn manifest_version(dir: &Path) -> Option<String> {
    let text = std::fs::read(dir.join("manifest.json")).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&text).ok()?;
    v.get("version")?.as_str().map(str::to_string)
}

/// `readlink -f`: every link followed; a missing last component is allowed.
fn readlink_f(p: &Path) -> Option<String> {
    if let Ok(r) = std::fs::canonicalize(p) {
        return Some(r.to_string_lossy().into_owned());
    }
    let mut path = p.to_path_buf();
    for _ in 0..40 {
        match std::fs::read_link(&path) {
            Ok(next) => {
                path = if next.is_absolute() {
                    next
                } else {
                    path.parent()?.join(next)
                };
            }
            Err(_) => {
                let parent = std::fs::canonicalize(path.parent()?).ok()?;
                return Some(
                    parent
                        .join(path.file_name()?)
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
    }
    None
}

pub fn cmd_setup() -> i32 {
    if !setup_install() {
        outln!("Everything omdrop sets up for you was already in place.");
    }
    let missing = prereqs_missing();
    if missing.is_empty() {
        outln!("\nReady. Turn receiving on from the bar, or run: omdrop on");
    } else {
        outln!("\nNot ready to receive yet:");
        for (_, say) in &missing {
            outln!("  - {say}");
        }
    }
    let offers = crate::driver::core_offers();
    if !offers.is_empty() {
        outln!("\nTo do:");
        for (_, say) in &offers {
            outln!("  - {say}");
        }
    }
    crate::links::skills_offer();
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_follow_the_bash() {
        assert_eq!(parse_duration("10m"), Ok(("10m".into(), 600)));
        assert_eq!(parse_duration("3"), Ok(("3m".into(), 180)));
        assert_eq!(parse_duration("5"), Ok(("5m".into(), 300)));
        assert_eq!(parse_duration("30s"), Ok(("30s".into(), 30)));
        assert_eq!(parse_duration("1hour"), Ok(("1hour".into(), 3600)));
        assert_eq!(parse_duration("2day"), Ok(("2day".into(), 172_800)));
        assert_eq!(parse_duration("0"), Ok(("0m".into(), 0)));
        for bad in ["", "m", "10x", "1.5h", "-1", "10 m", "once5"] {
            assert!(parse_duration(bad).is_err(), "{bad}");
        }
        assert!(parse_duration("99999999999999999999d").is_err());
    }

    #[test]
    fn the_radio_reason_is_its_last_line_without_the_timestamp() {
        assert_eq!(
            last_radio_line("12:00:00Z starting\n12:00:08Z supervisor did not start\n\n"),
            "supervisor did not start"
        );
        assert_eq!(last_radio_line("plain failure\n"), "plain failure");
        assert_eq!(last_radio_line(""), "");
    }

    #[test]
    fn the_core_receiver_replaces_only_the_program_in_execstart() {
        let template = "WorkingDirectory=@PLUGIN_DIR@\nExecStart=/usr/bin/python3 @PLUGIN_DIR@/bin/airdrop-serve.py --iface awdl0 --port 8771\nReadWritePaths=%h/Downloads";
        let plugin = Path::new("/home/u/.config/omarchy/plugins/netmojo.omdrop");
        let py = render_unit(template, plugin, None).unwrap();
        assert!(py.contains("ExecStart=/usr/bin/python3 /home/u/.config/omarchy/plugins/netmojo.omdrop/bin/airdrop-serve.py --iface awdl0 --port 8771"));
        let rx = Path::new("/usr/lib/omdrop-core/omdrop-receiver");
        let rs = render_unit(template, plugin, Some(rx)).unwrap();
        assert!(
            rs.contains(
                "\nExecStart=/usr/lib/omdrop-core/omdrop-receiver --iface awdl0 --port 8771\n"
            ),
            "{rs}"
        );
        assert!(
            rs.starts_with("WorkingDirectory=/home/u/.config/omarchy/plugins/netmojo.omdrop\n")
        );
        let odd = render_unit(
            template,
            plugin,
            Some(Path::new("/opt/my dir/omdrop-receiver")),
        )
        .unwrap();
        assert!(
            odd.contains("ExecStart=\"/opt/my dir/omdrop-receiver\" --iface"),
            "{odd}"
        );
    }

    #[test]
    fn paths_in_unit_text_are_one_word_and_never_add_lines() {
        let template = "WorkingDirectory=@PLUGIN_DIR@\nExecStart=/usr/bin/python3 @PLUGIN_DIR@/bin/airdrop-serve.py --iface awdl0";
        let spaced = render_unit(template, Path::new("/home/u/my 100% plugins"), None).unwrap();
        assert_eq!(
            spaced,
            "WorkingDirectory=/home/u/my 100%% plugins\nExecStart=/usr/bin/python3 \"/home/u/my 100%% plugins/bin/airdrop-serve.py\" --iface awdl0"
        );
        assert_eq!(
            render_unit(template, Path::new("/home/u/x\nExecStartPre=/evil"), None),
            None
        );
        assert_eq!(
            systemd_quote("/home/u/My Files").as_deref(),
            Some("\"/home/u/My Files\"")
        );
        assert_eq!(systemd_quote("/a$b%c").as_deref(), Some("/a$$b%%c"));
        assert_eq!(systemd_quote("/a\nb"), None);
    }

    #[test]
    fn a_send_that_died_does_not_block_off_and_a_live_one_does() {
        let tmp = tempfile::tempdir().unwrap();
        let mut live = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        std::fs::write(tmp.path().join(live.id().to_string()), "hume\n").unwrap();
        let mut dead = std::process::Command::new("true").spawn().unwrap();
        dead.wait().unwrap();
        let marker = tmp.path().join(dead.id().to_string());
        std::fs::write(&marker, "gone\n").unwrap();
        std::fs::write(tmp.path().join("junk"), "x\n").unwrap();
        assert_eq!(sending_to(tmp.path()), vec!["hume".to_string()]);
        assert!(!marker.exists());
        assert!(!tmp.path().join("junk").exists());
        live.kill().unwrap();
        live.wait().unwrap();
    }
}
