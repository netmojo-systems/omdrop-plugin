//! `status`, and the commands that show or set one thing: name, dir, sound,
//! limit, visibility, senders.
//!
//! There is no daemon of our own and no state file. `status` asks systemd,
//! so it stays right when the service dies, the timer fires, or someone runs
//! systemctl by hand.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::config::{
    cfg_get, cfg_set, effective_dir, effective_limit, effective_name, setting_get, setting_set,
};
use crate::ctx::{UNIT, WATCH, WINDOW, ctx};
use crate::proc::{capture, capture_ok, run, run_quiet};
use crate::util::{die, is_executable, is_space, py_json, strip_trailing_newlines};

pub fn have_unit() -> bool {
    run_quiet("systemctl", &["--user", "cat", UNIT]) == 0
}

pub fn receiving() -> bool {
    let (_, out) = capture("systemctl", &["--user", "is-active", UNIT]);
    strip_trailing_newlines(&String::from_utf8_lossy(&out)) == "active"
}

/// The shape of the window lives in the watcher's arguments, nowhere else:
/// `on` starts it with --once or --window <span> before the radio, so
/// `status` can name the window while the radio is still coming up, and
/// before the deadline exists.
pub fn watch_mode() -> Option<&'static str> {
    let exec = capture_ok(
        "systemctl",
        &[
            "--user",
            "show",
            &format!("{WATCH}.service"),
            "-p",
            "ExecStart",
            "--value",
        ],
    )?;
    if exec.contains("watch --once") {
        Some("once")
    } else if exec.contains("watch --window") {
        Some("timed")
    } else if exec.contains("watch") {
        Some("forever")
    } else {
        None
    }
}

/// Seconds until the pending window closes, or `None` when none is armed.
///
/// An --on-active timer is monotonic, so systemd answers on
/// NextElapseUSecMonotonic -- with a formatted span ("10min 4.99s"), not the
/// microseconds the name promises; systemd-analyze turns it back into a
/// number. The clock to compare against is CLOCK_MONOTONIC, which is NOT
/// /proc/uptime: uptime counts suspended time, and a laptop that slept read
/// minutes past its deadline and lost its countdown. If any step comes up
/// empty we report no window rather than guess -- wrong in the harmless direction.
pub fn window_remaining() -> Option<i64> {
    let span = capture_ok(
        "systemctl",
        &[
            "--user",
            "show",
            &format!("{WINDOW}.timer"),
            "-p",
            "NextElapseUSecMonotonic",
            "--value",
        ],
    )?;
    if span.is_empty() || span == "0" || span == "n/a" || span == "infinity" {
        return None;
    }
    let us = span_microseconds(&span)?;
    let now = clock_secs(libc::CLOCK_MONOTONIC)?;
    let secs = (us as f64 / 1e6 - now) as i64;
    (secs > 0).then_some(secs)
}

fn clock_secs(clock: libc::clockid_t) -> Option<f64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid timespec for clock_gettime to fill.
    if unsafe { libc::clock_gettime(clock, &mut ts) } != 0 {
        return None;
    }
    Some(ts.tv_sec as f64 + ts.tv_nsec as f64 / 1e9)
}

/// Seconds this computer has spent asleep since it booted. CLOCK_BOOTTIME
/// counts a suspend and CLOCK_MONOTONIC does not, so the difference grows by
/// the length of each sleep and holds still otherwise.
pub fn suspended_secs() -> Option<f64> {
    Some(clock_secs(libc::CLOCK_BOOTTIME)? - clock_secs(libc::CLOCK_MONOTONIC)?)
}

/// Whether the computer has slept since `before`, a `suspended_secs` reading.
/// A second is far above what two clock reads can drift apart while awake,
/// and far below any real suspend.
pub fn slept_since(before: f64) -> Option<bool> {
    suspended_secs().map(|now| now - before >= 1.0)
}

/// The µs line of `systemd-analyze timespan`, skipping the first line, which
/// echoes the input back and is all digits for a bare number.
pub fn span_microseconds(span: &str) -> Option<u64> {
    let (code, out) = capture("systemd-analyze", &["timespan", span]);
    if code != 0 {
        return None;
    }
    parse_timespan_output(&String::from_utf8_lossy(&out))
}

fn parse_timespan_output(out: &str) -> Option<u64> {
    out.lines().skip(1).find_map(|line| {
        let (_, value) = line.split_once(':')?;
        let value = value.trim_start_matches(' ');
        (!value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()))
            .then(|| value.parse().ok())
            .flatten()
    })
}

/// What the radio helper says about itself (`status --json`), when there is one.
pub struct Radio {
    pub visible: bool,
    pub reason: String,
    pub rx_proven: bool,
}

pub fn radio_status() -> Option<Radio> {
    let d = &ctx().discoverable;
    if !is_executable(d) {
        return None;
    }
    let (_, out) = capture(d, &["status", "--json"]);
    let rs = strip_trailing_newlines(&String::from_utf8_lossy(&out)).to_string();
    // Anchored on the value: `*"visible":*true*` matched
    // {"visible":false,...,"rx_proven":true} and drew the panel as visible.
    let reason = rs
        .lines()
        .filter_map(|line| {
            let i = line.rfind("\"reason\":\"")?;
            let rest = &line[i + 10..];
            let end = rest.find('"')?;
            Some(rest[..end].to_string())
        })
        .collect::<Vec<_>>()
        .join("\n");
    Some(Radio {
        visible: rs.contains("\"visible\":true"),
        reason,
        rx_proven: rs.contains("\"rx_proven\":true"),
    })
}

#[derive(Serialize)]
struct StatusJson {
    receiving: bool,
    /// null when the radio half is not installed: we genuinely do not know,
    /// and the panel must not draw that as "yes".
    visible: Option<bool>,
    remaining: Option<i64>,
    name: Option<String>,
    dir: String,
    mode: String,
    reason: Option<String>,
    rx_proven: bool,
    sound: bool,
    /// Who may send, with the allow-list size so the panel can warn that an
    /// empty list refuses everybody.
    visibility: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    receive_mode: Option<String>,
    senders: usize,
}

pub fn cmd_status(args: &[String]) -> i32 {
    let json = args.first().is_some_and(|a| a == "--json");
    let on = receiving();
    let mut mode = "off";
    if on {
        // The watcher answers for every window it started. Without one -- it
        // was killed, or the receiver was started by hand -- the timer is all there is.
        mode = watch_mode().unwrap_or_else(|| {
            if run_quiet(
                "systemctl",
                &["--user", "is-active", &format!("{WINDOW}.timer")],
            ) == 0
            {
                "timed"
            } else {
                "forever"
            }
        });
    }
    let left = window_remaining();
    let radio = radio_status();

    if json {
        let name = effective_name();
        let st = StatusJson {
            receiving: on,
            visible: radio.as_ref().map(|r| r.visible),
            remaining: left,
            name: (!name.is_empty()).then_some(name),
            dir: effective_dir(),
            mode: mode.to_string(),
            reason: radio
                .as_ref()
                .map(|r| r.reason.clone())
                .filter(|r| !r.is_empty()),
            rx_proven: radio.as_ref().is_some_and(|r| r.rx_proven),
            sound: sound_on(),
            visibility: visibility().to_string(),
            receive_mode: ctx().receiver.as_ref().map(|_| receive_mode().to_string()),
            senders: sender_count(),
        };
        outln!("{}", py_json(&st));
        return 0;
    }

    if !on {
        outln!("Not receiving");
        return 0;
    }
    // Same three windows the panel names, in the same words.
    let window = match left {
        Some(l) => format!("for {}:{:02} minutes", l / 60, l % 60),
        None if mode == "once" => "until one file arrives".to_string(),
        None => "until you turn it off".to_string(),
    };
    // In contacts mode a sender that identifies itself and is not on the list
    // is refused at /Discover, so it never sees this machine (measured
    // 2026-09-20). A sender we cannot identify is still answered there, and
    // refused at /Ask; the README carries that caveat.
    let mut audience = "to everyone".to_string();
    let mut empty = false;
    if visibility() == "contacts" {
        let known = sender_count();
        if known > 0 {
            audience = format!(
                "to {known} known sender{}",
                if known == 1 { "" } else { "s" }
            );
        } else {
            empty = true;
        }
    }
    let name = effective_name();
    match radio {
        Some(r) if r.visible => {
            if empty {
                outln!(
                    "Visible as \"{name}\" {window}, but nobody can send: contacts only, and the known-senders list is empty"
                );
            } else {
                outln!("Visible {audience} as \"{name}\" {window}");
            }
        }
        Some(_) => outln!(
            "Receiving as \"{name}\" -- {window}, but NOT visible: the radio side is not advertising"
        ),
        None => {
            let c = ctx();
            let shown = c
                .discoverable
                .strip_prefix(&c.proj)
                .unwrap_or(&c.discoverable);
            outln!(
                "Receiving as \"{name}\" -- {window} (cannot tell if anyone can see us: {} is missing)",
                shown.display()
            );
        }
    }
    0
}

/// The radar's sound effects. Off is remembered, so the panel is quiet from
/// the first frame next time rather than pinging once before it reads it.
pub fn sound_on() -> bool {
    setting_get("sound") != "off"
}

pub fn cmd_sound(args: &[String]) -> i32 {
    match args.first().map(String::as_str).unwrap_or("") {
        "" => {
            outln!("{}", if sound_on() { "on" } else { "off" });
            0
        }
        v @ ("on" | "off") => {
            setting_set("sound", v);
            0
        }
        _ => die("usage: omdrop sound [on|off]"),
    }
}

fn known_senders() -> PathBuf {
    ctx().contacts_dir.join("known-senders")
}

/// The allow-list's identifiers: every line that is not blank or a comment.
fn sender_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines().filter(|l| {
        let t = l.trim_start_matches(is_space);
        !t.is_empty() && !t.starts_with('#')
    })
}

/// How many senders the allow-list holds, ignoring comments and blank lines.
pub fn sender_count() -> usize {
    std::fs::read(known_senders())
        .map(|b| sender_lines(&String::from_utf8_lossy(&b)).count())
        .unwrap_or(0)
}

pub fn visibility() -> &'static str {
    let file = ctx().contacts_dir.join("visibility");
    if crate::util::read_trimmed(&file).as_deref() == Some("contacts") {
        "contacts"
    } else {
        "everyone"
    }
}

/// Contacts Only. The receiver reads `visibility` per request, so a change
/// applies at once; a running receiver is restarted anyway, as before.
pub fn cmd_visibility(args: &[String]) -> i32 {
    let Some(mode) = args.first() else {
        outln!("{}", visibility());
        return 0;
    };
    let c = ctx();
    let file = c.contacts_dir.join("visibility");
    match mode.as_str() {
        "everyone" => {
            let _ = std::fs::remove_file(&file);
            outln!("Anyone nearby can send to this machine.");
        }
        "contacts" => {
            let n = sender_count();
            let written = std::fs::create_dir_all(&c.contacts_dir)
                .and_then(|()| std::fs::write(&file, "contacts\n"));
            if let Err(e) = written {
                die(format!("omdrop could not write {}: {e}", file.display()));
            }
            outln!("Only known senders can send to this machine ({n} listed).");
            if n == 0 {
                outln!(
                    "The list is empty, so everything is refused. Add people with: omdrop senders add <email|phone>"
                );
            }
        }
        _ => die("usage: omdrop visibility [everyone|contacts]"),
    }
    if receiving() {
        run_quiet("systemctl", &["--user", "restart", UNIT]);
    }
    0
}

/// An Apple ID is an email address or a phone number, and the receiver
/// matches nothing else: anything else would sit in the list matching no one.
pub fn sender_id_valid(id: &str) -> bool {
    let ws = |c: char| c.is_whitespace();
    if id.contains('@') {
        let Some((local, domain)) = id.split_once('@') else {
            return false;
        };
        if local.is_empty() || local.contains(ws) || domain.contains('@') || domain.contains(ws) {
            return false;
        }
        // `[^@ ]+\.[^@ ]+`: some dot with something on both sides.
        return domain
            .char_indices()
            .any(|(i, c)| c == '.' && i > 0 && i + 1 < domain.len());
    }
    if id.is_empty()
        || !id
            .chars()
            .all(|c| c.is_ascii_digit() || "+().-".contains(c) || ws(c))
    {
        return false;
    }
    let digits = id.chars().filter(char::is_ascii_digit).count();
    (7..=15).contains(&digits)
}

pub fn cmd_senders(args: &[String]) -> i32 {
    let f = known_senders();
    let sub = args.first().map(String::as_str).unwrap_or("list");
    let rest = args.get(1..).unwrap_or(&[]);
    match sub {
        "list" => {
            let text = std::fs::read(&f).map(|b| String::from_utf8_lossy(&b).into_owned());
            if rest.first().is_some_and(|a| a == "--json") {
                // For the panel: the identifiers exactly as stored, so a row's
                // remove names the same line the file holds. The exit status
                // is grep's, as it always was: 1 for none, 2 for no file.
                let (ids, code) = match &text {
                    Ok(t) => {
                        let ids: Vec<String> =
                            sender_lines(t).map(|l| l.trim().to_string()).collect();
                        let code = if ids.is_empty() { 1 } else { 0 };
                        (ids, code)
                    }
                    Err(_) => (Vec::new(), 2),
                };
                outln!("{}", py_json(&ids));
                return code;
            }
            let lines: Vec<&str> = match &text {
                Ok(t) => sender_lines(t).collect(),
                Err(_) => Vec::new(),
            };
            if lines.is_empty() {
                outln!("(no known senders yet)");
            } else {
                for l in lines {
                    outln!("{l}");
                }
            }
            0
        }
        "add" => {
            if rest.is_empty() {
                die("usage: omdrop senders add <email-or-phone> [...]");
            }
            for id in rest {
                if !sender_id_valid(id) {
                    die(format!(
                        "\"{id}\" is not an email address or a phone number. Use the email or phone number of their Apple ID."
                    ));
                }
            }
            if let Err(e) = add_senders(&f, rest) {
                die(format!("omdrop could not write {}: {e}", f.display()));
            }
            outln!("Added. {} known now.", sender_count());
            0
        }
        "remove" | "rm" => {
            if rest.is_empty() {
                die("usage: omdrop senders remove <email-or-phone> [...]");
            }
            if !f.is_file() {
                die("no known-senders list yet");
            }
            if let Err(e) = remove_senders(&f, rest) {
                die(format!("omdrop could not write {}: {e}", f.display()));
            }
            outln!("Removed. {} known now.", sender_count());
            0
        }
        _ => die("usage: omdrop senders [list|add <id>|remove <id>]"),
    }
}

fn add_senders(f: &Path, ids: &[String]) -> std::io::Result<()> {
    if let Some(dir) = f.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut text = match std::fs::read(f) {
        Ok(b) => String::from_utf8_lossy(&b).into_owned(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e),
    };
    let original = text.len();
    for id in ids {
        if text.lines().any(|l| l == id) {
            continue;
        }
        // An entry appended to a last line with no newline would be glued to it.
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(id);
        text.push('\n');
    }
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(f)?;
    file.write_all(&text.as_bytes()[original..])
}

fn remove_senders(f: &Path, ids: &[String]) -> std::io::Result<()> {
    let text = String::from_utf8_lossy(&std::fs::read(f)?).into_owned();
    let mut out = String::new();
    for line in text.lines() {
        if !ids.iter().any(|id| id == line) {
            out.push_str(line);
            out.push('\n');
        }
    }
    crate::util::atomic_write(f, ".known-senders.", out.as_bytes(), 0o600)
}

/// After a set the receiver refused, put the old value back and say so.
fn restart_or_roll_back(key: &str, old: &str, refused: String) {
    if !receiving() {
        return;
    }
    if run("systemctl", &["--user", "restart", UNIT]) != 0 {
        cfg_set(key, old);
        run_quiet("systemctl", &["--user", "restart", UNIT]);
        die(format!("{refused}\nsystemctl --user status {UNIT}"));
    }
}

pub fn cmd_name(args: &[String]) -> i32 {
    let Some(new) = args.first() else {
        outln!("{}", effective_name());
        return 0;
    };
    if new.chars().all(is_space) {
        die("The name can't be empty.");
    }
    let n = new.chars().count();
    if n > 63 {
        die(format!(
            "The name can be 63 characters at most; this one has {n}."
        ));
    }
    if new.contains(['/', '\\']) {
        die("The name can't contain / or \\.");
    }
    if new.chars().any(char::is_control) {
        die("The name can't contain control characters.");
    }
    let old = cfg_get("name");
    if !cfg_set("name", new) {
        die(format!("could not write {}", ctx().config.display()));
    }
    // The receiver reads config.toml once, at start: restart to pick it up,
    // and if it refuses the new name, put the old one back rather than leave
    // a dead receiver behind a config the user thinks took effect.
    restart_or_roll_back(
        "name",
        &old,
        format!("the receiver refused \"{new}\", so it is still \"{old}\"."),
    );
    outln!("Macs will see \"{new}\"");
    0
}

/// The unit is hardened with ProtectHome=read-only, so the download folder
/// has to be named in ReadWritePaths or the receiver cannot write there; a
/// drop-in names exactly the folder in use.
pub fn cmd_dir(args: &[String]) -> i32 {
    let Some(arg) = args.first() else {
        outln!("{}", effective_dir());
        return 0;
    };
    let want: PathBuf = if arg == "--pick" {
        match crate::pick::pick("folder", &effective_dir(), "Save received files to") {
            Ok(paths) => paths.into_iter().next().unwrap_or_default(),
            Err(code) => crate::util::exit(code),
        }
    } else {
        match arg.strip_prefix('~') {
            Some(rest) => PathBuf::from(format!("{}{rest}", crate::util::home())),
            None => PathBuf::from(arg),
        }
    };
    if !want.is_dir() {
        die(format!(
            "{}: not a directory (create it first)",
            want.display()
        ));
    }
    let new = std::fs::canonicalize(&want).unwrap_or(want);
    if !owned_by_me(&new) {
        die(format!(
            "{}: you do not own it; received files land here as you",
            new.display()
        ));
    }
    let new_s = new.to_string_lossy().into_owned();
    // One word in the drop-in, whatever the name holds: unquoted, "My Files"
    // was two paths and `%` a specifier. A line break would add unit lines.
    let Some(quoted) = crate::window::systemd_quote(&new_s) else {
        die(format!(
            "{new_s}: a folder whose name holds a line break cannot be given to the receiving service"
        ));
    };
    let old = cfg_get("download_dir");
    if !cfg_set("download_dir", &new_s) {
        die(format!("could not write {}", ctx().config.display()));
    }
    let dropin = ctx()
        .config_home
        .join("systemd/user")
        .join(format!("{UNIT}.d"));
    let _ = std::fs::create_dir_all(&dropin);
    // An empty assignment resets the list the base unit set; without it a
    // drop-in only ADDS, leaving the old folder writable and listing it twice.
    let body = format!(
        "# Written by omdrop. Declares exactly the paths the receiver may write.\n[Service]\nReadWritePaths=\nReadWritePaths={quoted}\nReadWritePaths=%h/.omdrop\nReadWritePaths=-%t/omdrop/debug\n"
    );
    let conf = dropin.join("10-download-dir.conf");
    if let Err(e) = std::fs::write(&conf, body) {
        errln!("omdrop: {}: {e}", conf.display());
    }
    run("systemctl", &["--user", "daemon-reload"]);
    if receiving() && run("systemctl", &["--user", "restart", UNIT]) != 0 {
        if !old.is_empty() {
            cfg_set("download_dir", &old);
        }
        run_quiet("systemctl", &["--user", "restart", UNIT]);
        let was = if old.is_empty() {
            "the default".to_string()
        } else {
            old
        };
        die(format!(
            "the receiver refused {new_s}, so it is still {was}.\nsystemctl --user status {UNIT}"
        ));
    }
    outln!("Files will land in {new_s}");
    0
}

fn owned_by_me(p: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid cannot fail.
    std::fs::metadata(p).is_ok_and(|m| m.uid() == unsafe { libc::geteuid() })
}

/// Where the file chooser opens for a send: the folder the last sent file
/// came from, while it still exists, and the download folder otherwise.
pub fn send_start_dir() -> String {
    let d = setting_get("send_from");
    if !d.is_empty() && Path::new(&d).is_dir() {
        d
    } else {
        effective_dir()
    }
}

pub fn cmd_limit(args: &[String]) -> i32 {
    if args.is_empty() {
        outln!("{}%", effective_limit());
        return 0;
    }
    if args.len() != 1 {
        die("usage: omdrop limit [PERCENT]");
    }
    let raw = &args[0];
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        die("limit: an integer from 1 to 90");
    }
    let digits = raw.trim_start_matches('0');
    let new: u32 = if digits.is_empty() {
        0
    } else {
        digits.parse().unwrap_or(u32::MAX)
    };
    if !(1..=90).contains(&new) {
        die("limit: an integer from 1 to 90");
    }
    let old = effective_limit();
    if !cfg_set("max_receive_percent", &new.to_string()) {
        die(format!("could not write {}", ctx().config.display()));
    }
    restart_or_roll_back(
        "max_receive_percent",
        &old,
        format!("the receiver refused {new}%, so the limit is still {old}%."),
    );
    outln!("A transfer may use up to {new}% of currently free download-disk space.");
    0
}

/// Match the receiver's fail-closed policy for unreadable or invalid settings.
fn receive_mode() -> &'static str {
    match std::fs::read_to_string(ctx().contacts_dir.join("receive-mode")) {
        Ok(value) if value.trim() == "auto" => "auto",
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => "auto",
        _ => "ask",
    }
}

/// Persist atomically; a running receiver reads the setting on every request.
pub fn cmd_receive_mode(args: &[String]) -> i32 {
    if args.is_empty() {
        outln!("{}", receive_mode());
        return 0;
    }
    if args.len() != 1 || !matches!(args[0].as_str(), "auto" | "ask") {
        die("usage: omdrop receive-mode [auto|ask]");
    }
    if ctx().receiver.is_none() {
        die("receive confirmation requires omdrop-core's Rust receiver");
    }
    if let Err(e) = std::fs::create_dir_all(&ctx().contacts_dir) {
        die(format!("could not create settings directory: {e}"));
    }
    let path = ctx().contacts_dir.join("receive-mode");
    if let Err(e) = crate::util::atomic_write(
        &path,
        ".receive-mode.",
        format!("{}\n", args[0]).as_bytes(),
        0o600,
    ) {
        die(format!("could not save receive mode: {e}"));
    }
    outln!("{}", args[0]);
    0
}

/// Called only by a desktop action. A late reply cannot recreate a request.
pub fn cmd_receive_answer(args: &[String]) -> i32 {
    if args.len() != 2 {
        die("usage: omdrop receive-answer TOKEN accept|decline");
    }
    if let Err(e) = omdrop_proto::receive_answer::send(
        &omdrop_proto::receive_answer::directory(),
        &args[0],
        &args[1],
    ) {
        die(format!("receive request is no longer available: {e}"));
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sender_ids_are_emails_or_phone_numbers() {
        for ok in [
            "a@b.co",
            "brent@example.com",
            "+1 (604) 555-0100",
            "6045550100",
            "1234567",
        ] {
            assert!(sender_id_valid(ok), "{ok}");
        }
        for bad in [
            "a@b",
            "@b.co",
            "a@.co",
            "a@b.",
            "a b@c.d",
            "a@b@c.d",
            "123456",
            "1234567890123456",
            "abc",
            "",
        ] {
            assert!(!sender_id_valid(bad), "{bad}");
        }
    }

    #[test]
    fn timespan_reads_the_microseconds_line_not_the_echo() {
        assert_eq!(
            parse_timespan_output("Original: 5\n      µs: 5000000\n   Human: 5s\n"),
            Some(5_000_000)
        );
        assert_eq!(
            parse_timespan_output(
                "Original: 10min 4.99s\n      µs: 604990000\n   Human: 10min 4.990s\n"
            ),
            Some(604_990_000)
        );
        assert_eq!(parse_timespan_output("Original: 5\n"), None);
    }

    #[test]
    fn comments_and_blank_lines_are_not_senders() {
        let ids: Vec<_> = sender_lines("# c\n\n  \na@b.co\n  # x\n +1 604 555 0100 \n").collect();
        assert_eq!(ids, vec!["a@b.co", " +1 604 555 0100 "]);
    }

    #[test]
    fn removing_the_last_sender_empties_the_list() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("known-senders");
        std::fs::write(&f, "a@b.co").unwrap();
        add_senders(&f, &["c@d.co".to_string(), "a@b.co".to_string()]).unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "a@b.co\nc@d.co\n");
        remove_senders(&f, &["a@b.co".to_string(), "c@d.co".to_string()]).unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "");
    }
}
