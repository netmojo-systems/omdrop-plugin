//! Sending, and the peers the radio can hear.
//!
//! Sending needs no service and no window of its own: it is one outbound
//! connection to a device the radio can already hear, made by send-to-peer,
//! which ships with the driver because the peer table it reads is the
//! firmware's. It dials a peer's EUI-64 link-local address directly: an
//! Apple device in Everyone mode answers /Discover while publishing no
//! `_airdrop._tcp` instance at all.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::config::{effective_name, setting_set};
use crate::ctx::{DEFAULT_SEND_WAIT, DEFAULT_WINDOW, ctx};
use crate::driver::{awdl_link_local, radio_pkg, radio_update};
use crate::identity::{Out, id};
use crate::names::{Lookup, Watch};
use crate::proc::{
    Forwarded, LineReader, Read1, cancelled, capture_merged, pipe, run_cancellable, spawn_group,
    spawn_session, stop_group, trap_signals, untrap_signals, wait_cancellable,
};
use crate::util::{
    after_first, after_last_slash, contains_in_order, die, is_executable, py_json, shell_quote,
};

/// A row of `send-to-peer --list`: address, signal (or `?`), endpoint, and
/// the name column `--names` fills. The same pattern the bash matched with
/// `^(([0-9a-f]{2}:){5}[0-9a-f]{2})\s+(-?[0-9]+|\?) dBm\s+\S+\s*(.*)$`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub mac: String,
    pub rssi: String,
    pub name: String,
}

/// An address as the sender prints one: `aa:bb:cc:dd:ee:ff`, lower-case.
pub fn is_mac(s: &str) -> bool {
    s.len() == 17
        && s.bytes().enumerate().all(|(i, c)| {
            if i % 3 == 2 {
                c == b':'
            } else {
                c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
            }
        })
}

pub fn parse_row(line: &str) -> Option<Row> {
    let mac = line.get(..17).filter(|m| is_mac(m))?;
    let rest = &line[17..];
    let after_ws = rest.trim_start_matches(crate::util::is_space);
    if after_ws.len() == rest.len() {
        return None;
    }
    let sig_len = if after_ws.starts_with('?') {
        1
    } else {
        let digits_from = usize::from(after_ws.starts_with('-'));
        let n = after_ws[digits_from..]
            .bytes()
            .take_while(u8::is_ascii_digit)
            .count();
        if n == 0 {
            return None;
        }
        digits_from + n
    };
    let rssi = &after_ws[..sig_len];
    let rest = after_ws[sig_len..].strip_prefix(" dBm")?;
    let after_ws = rest.trim_start_matches(crate::util::is_space);
    if after_ws.len() == rest.len() {
        return None;
    }
    let endpoint_len = after_ws
        .find(crate::util::is_space)
        .unwrap_or(after_ws.len());
    if endpoint_len == 0 {
        return None;
    }
    let name = after_ws[endpoint_len..].trim_start_matches(crate::util::is_space);
    Some(Row {
        mac: mac.to_string(),
        rssi: rssi.to_string(),
        name: name.to_string(),
    })
}

pub fn placeholder(name: &str) -> bool {
    matches!(name, "" | "(no response)" | "(anonymous)")
}

/// Whether a window is open: awdl0 has its link-local address and the radio
/// helper reports itself visible. The address alone outlives `omdrop off`.
/// The helper's answer is read as JSON, so any valid spelling of it counts.
fn radio_on() -> bool {
    if !awdl_link_local() {
        return false;
    }
    let d = &ctx().discoverable;
    if !is_executable(d) {
        return true;
    }
    let (_, out) = crate::proc::capture(d, &["status", "--json"]);
    serde_json::from_slice::<serde_json::Value>(&out)
        .ok()
        .and_then(|v| v.as_object().and_then(|o| o.get("visible")).cloned())
        == Some(serde_json::Value::Bool(true))
}

/// The sender, told which root helper to use: the one `on` chose. Left to
/// itself, a core send-to-peer installed beside a 0.9.x driver would pick
/// the core omdrop-radio, which has no backend hooks to list peers with.
fn sender_cmd() -> Command {
    let c = ctx();
    let mut cmd = Command::new(&c.sender);
    if is_executable(&c.discoverable) {
        cmd.env("OMDROP_DISCOVERABLE", &c.discoverable);
    }
    cmd
}

/// `"$SENDER" --help 2>&1 | grep -q PATTERN`: what the installed driver's
/// sender understands. The driver and this command are versioned apart.
fn sender_help_has(pattern: &str) -> bool {
    let mut cmd = sender_cmd();
    cmd.arg("--help");
    let (_, out) = capture_merged(cmd);
    String::from_utf8_lossy(&out).contains(pattern)
}

fn describe_files(files: &[OsString]) -> String {
    if files.len() == 1 {
        after_last_slash(&files[0]).to_string_lossy().into_owned()
    } else {
        format!("{} files", files.len())
    }
}

fn require_sender() {
    if !is_executable(&ctx().sender) {
        die(format!(
            "The program that sends files is not installed. It comes with the {}. {}",
            radio_pkg(),
            radio_update()
        ));
    }
    if !awdl_link_local() {
        die(
            "The Apple-compatible radio is not running, so nobody can be heard and nothing can be sent. Start it with: omdrop on 10m",
        );
    }
}

pub fn cmd_send(args: &[OsString]) -> i32 {
    let c = ctx();
    let mut to = String::new();
    let mut wait = DEFAULT_SEND_WAIT.to_string();
    let (mut verbose, mut pick) = (false, false);
    let mut rest: Vec<OsString> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].to_string_lossy();
        match a.as_ref() {
            "--to" => {
                i += 1;
                to = args
                    .get(i)
                    .map(|v| v.to_string_lossy().into_owned())
                    .unwrap_or_else(|| {
                        die("send --to: the address of a device, as listed by: omdrop peers")
                    });
            }
            "--wait" => {
                i += 1;
                wait = args
                    .get(i)
                    .map(|v| v.to_string_lossy().into_owned())
                    .unwrap_or_else(|| die("send --wait: a number of seconds"));
            }
            "-v" | "--verbose" => verbose = true,
            // The panel's route: ask for the files in a chooser, after
            // everything that could refuse the send has been checked.
            "--pick" => pick = true,
            // A filename may begin with a dash; `--` is how they say so.
            "--" => {
                i += 1;
                break;
            }
            s if s.starts_with("--to=") => to = s["--to=".len()..].to_string(),
            s if s.starts_with("--wait=") => wait = s["--wait=".len()..].to_string(),
            s if s.starts_with('-') => die(format!("send: no such option {s}")),
            // Which positional is a file and which the recipient is decided
            // by the filesystem, not by position, so `send fred photo.jpg`
            // and `send photo.jpg fred` both work.
            _ => rest.push(args[i].clone()),
        }
        i += 1;
    }
    rest.extend(args.iter().skip(i).cloned());

    // Web links are payloads, not recipients. With --to, every other
    // argument is a file; without it, one nonexistent path can name the recipient.
    let (mut files, mut urls, mut absent) = (
        Vec::<OsString>::new(),
        Vec::<String>::new(),
        Vec::<String>::new(),
    );
    for f in &rest {
        let s = f.to_string_lossy();
        if crate::links::web_url(&s) {
            urls.push(s.into_owned());
        } else if !to.is_empty() || Path::new(f).exists() {
            files.push(f.clone());
        } else {
            absent.push(s.into_owned());
        }
    }
    match absent.len() {
        0 => {}
        1 => to = absent.remove(0),
        _ => die(format!(
            "send: none of these is a file, and only one can be the recipient: {}",
            absent.join(" ")
        )),
    }

    if pick {
        if !rest.is_empty() {
            die("send --pick: the chooser picks the files, so name only the recipient, with --to");
        }
        require_sender();
        let title = format!(
            "Send to {}",
            if to.is_empty() {
                "a nearby device"
            } else {
                &to
            }
        );
        files = match crate::pick::pick("files", &crate::status::send_start_dir(), &title) {
            Ok(paths) => paths.into_iter().map(OsString::from).collect(),
            Err(code) => crate::util::exit(code),
        };
        if files.is_empty() {
            crate::util::exit(1);
        }
        // Remembered on choosing, not on arriving: the folder is where they
        // keep things to send, whether or not these got through.
        setting_set(
            "send_from",
            &crate::util::dirname(&files[0]).to_string_lossy(),
        );
        // The first line the panel hears: the chooser has closed with files.
        outln!("Preparing {}...", describe_files(&files));
    }

    // A shortcut's web link goes as that link rather than as a file;
    // invalid shortcuts and non-web links remain ordinary files.
    let mut kept = Vec::new();
    let mut notes = Vec::new();
    for f in files {
        match crate::links::is_link_file(&f)
            .then(|| crate::links::link_target(Path::new(&f)))
            .flatten()
        {
            Some(url) => {
                notes.push(format!(
                    "Sending the link in {}, so it opens in their browser: {url}",
                    after_last_slash(&f).to_string_lossy()
                ));
                urls.push(url);
            }
            None => kept.push(f),
        }
    }
    let files = kept;
    if !urls.is_empty() && !files.is_empty() {
        die("Send links and files separately: one transfer carries one or the other.");
    }
    for n in &notes {
        outln!("{n}");
    }
    if files.is_empty() && urls.is_empty() {
        die(
            "usage: omdrop send [RECIPIENT] FILE...|URL... [--wait SECONDS]\n  RECIPIENT is a device name, as shown by `omdrop peers -n`, or part of an address.\n  A URL is an http or https link, which opens in the recipient's browser.",
        );
    }
    let mut names: Vec<OsString> = Vec::new();
    for f in &files {
        let p = Path::new(f);
        let shown = f.to_string_lossy();
        if !p.exists() {
            die(format!("{shown}: there is no such file"));
        }
        if p.is_dir() {
            die(format!(
                "{shown}: a folder cannot be sent -- send files, or compress the folder first"
            ));
        }
        if !p.is_file() || !crate::util::is_readable(p) {
            die(format!("{shown}: not a file that can be read"));
        }
        // The device stores each file under its name alone, so two files of
        // one name would arrive as one. Said here, before anyone waits.
        let base = after_last_slash(f);
        if names.contains(&base) {
            die(format!(
                "Two of these files are called {}, and the device would keep only one. Rename one, or send them separately.",
                base.to_string_lossy()
            ));
        }
        names.push(base);
    }
    // Checked here, so a typo costs a sentence instead of a polkit prompt.
    if wait.is_empty() || !wait.bytes().all(|b| b.is_ascii_digit()) {
        die(
            "send --wait: whole seconds, or 0 to give up the moment the device refuses a connection",
        );
    }
    // Names are not lowercased: the sender matches case-insensitively, and
    // folding the case here would only corrupt the message it prints back.
    if to.contains('\n') {
        die("send: a recipient is one name or address, not several lines");
    }
    if !is_executable(&c.sender) {
        die(format!(
            "The program that sends files is not installed. It comes with the {}. {}",
            radio_pkg(),
            radio_update()
        ));
    }
    // A driver older than 0.5.0 sends one file only; its usage line says so.
    if files.len() > 1 && !sender_help_has("[file ...]") {
        die(format!(
            "Sending several files at once needs a newer {}. {}",
            radio_pkg(),
            radio_update()
        ));
    }
    if !urls.is_empty() && !sender_help_has("--url") {
        die(format!(
            "Sending a link needs a newer {}. {}",
            radio_pkg(),
            radio_update()
        ));
    }

    let payload: Vec<String> = urls
        .iter()
        .cloned()
        .chain(files.iter().map(|f| f.to_string_lossy().into_owned()))
        .collect();

    // A closed window hears nobody, so a send to a named device opens one,
    // as the panel's Send section does. Without a name the window must be
    // open first: in a window just opened, "the only device heard" is
    // whichever device spoke first.
    if !radio_on() {
        let example: String = payload
            .iter()
            .map(|p| format!(" {}", shell_quote(p)))
            .collect();
        if to.is_empty() {
            die(format!(
                "Omdrop is off, so no device can be heard. Name the device, and omdrop turns itself on to find it:\n  omdrop send NAME{example}\nOr turn it on first, with: omdrop on"
            ));
        }
        outln!(
            "Omdrop is off. Turning it on for {DEFAULT_WINDOW}, so nearby devices can be heard..."
        );
        auto_start(c.command_path());
        if !radio_on() {
            die(
                "Omdrop turned on, but the radio is not up yet, so nothing was sent. Try again in a few seconds.",
            );
        }
        outln!(
            "Omdrop is on, and visible nearby until the window ends. Turn it off sooner with: omdrop off"
        );
    }

    let peer = choose_peer(&to, &payload);

    // The name Apple devices already know this computer by, so the prompt
    // on their screen says the same thing whichever way the file is going.
    let mut cmd = sender_cmd();
    cmd.arg("--name")
        .arg(effective_name())
        .arg("--wait")
        .arg(&wait)
        .arg("--mac")
        .arg(&peer);
    for u in &urls {
        cmd.arg("--url").arg(u);
    }
    cmd.arg("--").args(&files);

    // Until this process exits, `omdrop off` knows a transfer is running.
    crate::window::mark_sending(if to.is_empty() { &peer } else { &to });

    if verbose {
        // For bug reports: the protocol log, and redacted dumps of each
        // request and answer in the runtime directory.
        cmd.env("OMDROP_DEBUG", "1");
        return run_cancellable(&mut cmd);
    }
    send_narrated(&mut cmd)
}

/// `omdrop on` for a send that found Omdrop off. A cancel while it runs is
/// passed on, and `on` undoes its start under its own identity lock, so no
/// other window can be caught by the undo. A cancel that arrives once `on`
/// has finished leaves its window open, as after any `omdrop on`.
fn auto_start(omdrop: &Path) {
    match crate::proc::run_no_stdout_forwarding(omdrop, &["on"]) {
        Forwarded::Exited(0) => untrap_signals(),
        Forwarded::Cancelled(_) => cancelled(None),
        Forwarded::Exited(_) => {
            untrap_signals();
            die("Omdrop could not be turned on, so nothing was sent.");
        }
    }
}

/// The sender speaks in debug log lines, deliberately: a transfer that goes
/// wrong is a protocol problem and that log is how it gets diagnosed.
/// Somebody sending a photo needs four sentences out of it.
pub fn narrate(line: &str) -> Option<(bool, String)> {
    let out = |s: String| Some((false, s));
    let err = |s: String| Some((true, s));
    if line.contains("; asking") {
        out("Asking them to accept it...".into())
    } else if line.contains("ASK -> accepted") {
        out("They accepted. Sending...".into())
    } else if line.contains("ASK -> declined") {
        err("They declined it.".into())
    } else if line.contains("ASK failed: ") {
        err(format!(
            "They never answered: {}",
            after_first(line, "ASK failed: ")
        ))
    } else if line.contains("UPLOAD failed: ") {
        err(format!(
            "The transfer failed: {}",
            after_first(line, "UPLOAD failed: ")
        ))
    } else if contains_in_order(line, &["UPLOAD ", " -> FAILED"]) {
        err("The transfer failed.".into())
    } else if contains_in_order(line, &["UPLOAD ", " -> ok ("]) {
        let rest = after_first(line, "UPLOAD ");
        let name = rest.find(" -> ok ").map_or(rest, |i| &rest[..i]);
        let stat = line.rfind("-> ok (").map_or(line, |i| &line[i + 7..]);
        out(format!(
            "Sent {name} ({})",
            stat.strip_suffix(')').unwrap_or(stat)
        ))
    } else if contains_in_order(line, &["LINK ", " -> ok"]) {
        // A link is delivered by the accepted Ask: there is no upload.
        let rest = after_first(line, "LINK ");
        out(format!(
            "Sent {}",
            rest.strip_suffix(" -> ok").unwrap_or(rest)
        ))
    } else {
        None
    }
}

/// The sender's `UPLOAD progress <sent>/<total>` line, as owly's
/// `\r<sent> / <total> bytes` step, which file managers already read.
pub fn progress(line: &str) -> Option<String> {
    let rest = line.split_once("UPLOAD progress ")?.1;
    let (sent, total) = rest.trim().split_once('/')?;
    let (sent, total) = (sent.parse::<u64>().ok()?, total.parse::<u64>().ok()?);
    Some(format!("\r{sent} / {total} bytes"))
}

/// The sender's "<address> never opened 8770; on an iPhone, open a share
/// sheet..." names a port and a macOS daemon. What the person can act on
/// depends on the identity this computer is sending with: a self-signed one
/// only reaches devices set to Everyone.
fn unreachable_message() -> &'static str {
    let st = id(&["status", "--json"], Out::Capture, false);
    let d: serde_json::Value = serde_json::from_str(&st.stdout).unwrap_or(serde_json::Value::Null);
    let field = |k: &str| match d.get(k) {
        Some(serde_json::Value::String(s)) if !s.is_empty() => s.clone(),
        _ => "-".to_string(),
    };
    match (field("window").as_str(), field("mode").as_str()) {
        ("self-signed", "1password") => {
            "1Password locked; using self-signed certificates. Peers must be in \"Everyone\" mode."
        }
        ("self-signed", _) => "Using self-signed certificates. Peers must be in \"Everyone\" mode.",
        _ => {
            "It is not accepting files right now. On an iPhone, open a share sheet to wake AirDrop, then try again."
        }
    }
}

/// The sender as its own process group, its log turned into sentences and
/// its complaints passed through on their way to stderr. The exit status is
/// the sender's: the narration always succeeds.
fn send_narrated(cmd: &mut Command) -> i32 {
    let (Ok((out_r, out_w)), Ok((err_r, err_w))) = (pipe(), pipe()) else {
        die("omdrop could not create a pipe.");
    };
    cmd.stdout(Stdio::from(out_w)).stderr(Stdio::from(err_w));
    trap_signals();
    let spawned = spawn_group(cmd);
    // Our copies of the write ends go, or the readers never see EOF.
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
    let mut child = match spawned {
        Ok(c) => c,
        Err(e) => {
            untrap_signals();
            return crate::proc::spawn_error(cmd, &e);
        }
    };
    let errors = std::thread::spawn(move || {
        let mut reader = LineReader::new(err_r);
        // Stops at a caught signal too (`Read1::Signal`): the main thread is
        // cancelling and will exit, and nothing more here is worth waiting for.
        while let Read1::Line(l) = reader.read_line(None) {
            let line = String::from_utf8_lossy(&l);
            if line.contains(" never opened ") {
                errln!("{}", unreachable_message());
            } else {
                errln!("{line}");
            }
        }
    });
    let mut reader = LineReader::new(out_r);
    // A progress step ends with no newline, so the next sentence starts on its own line.
    let mut stepping = false;
    loop {
        match reader.read_line(None) {
            Read1::Line(l) => {
                let line = String::from_utf8_lossy(&l);
                if let Some(step) = progress(&line) {
                    let mut err = std::io::stderr().lock();
                    let _ = std::io::Write::write_all(&mut err, step.as_bytes())
                        .and_then(|()| std::io::Write::flush(&mut err));
                    stepping = true;
                    continue;
                }
                let Some((error, s)) = narrate(&line) else {
                    continue;
                };
                if std::mem::take(&mut stepping) {
                    errln!("");
                }
                if error {
                    errln!("{s}");
                } else {
                    outln!("{s}");
                }
            }
            Read1::Signal => {
                if stepping {
                    errln!("");
                }
                cancelled(Some(&mut child))
            }
            Read1::Eof | Read1::Timeout => break,
        }
    }
    if stepping {
        errln!("");
    }
    let rc = wait_cancellable(&mut child, None).unwrap_or(1);
    // The sender's stderr can outlive it (an advertiser it started still
    // holding it), so wait for the last complaint without ever giving up a
    // cancel: a blocking join here once ignored Ctrl-C forever.
    while !errors.is_finished() {
        if crate::proc::caught().is_some() {
            cancelled(None);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = errors.join();
    untrap_signals();
    rc
}

/// Which device the payload is going to. Chosen here rather than by the
/// sender, whose word for this is `--mac` and whose refusals would name an
/// option `omdrop send` does not have; and an AWDL address is randomised
/// per session, so any unambiguous part of one is accepted.
///
/// A table that could not be read is NOT an empty room: reporting a helper
/// that never ran as "nobody is nearby" sent a debugging session after the
/// radio when the answer was polkit. Only exit 1 means an empty table.
fn choose_peer(to: &str, payload: &[String]) -> String {
    let c = ctx();
    let want = to.to_lowercase();
    // A colon, or a full 12-hex MAC, is an address; anything else a name --
    // strictly, because device names are often pure hex ("f0011").
    let full_mac = want.len() == 12
        && want
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    let by_name = !want.is_empty() && !want.contains(':') && !full_mac;
    let (listing, rc) = if by_name {
        find_by_name(&want, to)
    } else {
        let mut list = sender_cmd();
        list.arg("--list");
        let (rc, out) = capture_merged(list);
        (
            crate::util::strip_trailing_newlines(&String::from_utf8_lossy(&out)).to_string(),
            rc,
        )
    };
    if rc != 0 && rc != 1 {
        die(&listing);
    }
    let rows: Vec<Row> = listing.lines().filter_map(parse_row).collect();
    if rows.is_empty() {
        if by_name {
            die(format!(
                "No Apple device was heard in {} seconds. Open AirDrop on \"{to}\" so it can be heard, then try again.",
                c.name_wait
            ));
        }
        die(
            "No nearby Apple device found. A window is what finds them, so open one first:  omdrop on 10m",
        );
    }
    let mut matches = Vec::new();
    let mut exact = Vec::new();
    for row in &rows {
        let name = row.name.to_lowercase();
        if want.is_empty() {
            matches.push(row);
        } else if by_name {
            if name.contains(&want) && name != "(no response)" && name != "(anonymous)" {
                matches.push(row);
            }
            if name == want {
                exact.push(row);
            }
        } else if row.mac.contains(&want) {
            matches.push(row);
        }
    }
    // Prefer an exact name, but still refuse two devices with that name.
    if !exact.is_empty() {
        matches = exact;
    }
    if matches.is_empty() {
        if by_name {
            let answered: Vec<String> = listing.split('\n').map(|l| format!("  {l}")).collect();
            die(format!(
                "No device called \"{to}\" answered in {} seconds. A device gives its name\nonly while it is ready to receive, so open AirDrop on it and try again. What answered:\n{}",
                c.name_wait,
                answered.join("\n")
            ));
        }
        die(format!(
            "No device matching \"{want}\" was found. See what is nearby:  omdrop peers"
        ));
    }
    if matches.len() > 1 {
        // Each line is the command to run: the files are already in hand,
        // and the address is six random bytes nobody should have to retype.
        let quoted: String = if payload.is_empty() {
            " ''".to_string()
        } else {
            payload
                .iter()
                .map(|p| format!(" {}", shell_quote(p)))
                .collect()
        };
        let lines: String = matches
            .iter()
            .map(|r| {
                let nm = if r.name.is_empty() {
                    String::new()
                } else {
                    format!(", {}", r.name)
                };
                format!(
                    "\n  omdrop send --to {}{quoted}   ({} dBm{nm})",
                    r.mac, r.rssi
                )
            })
            .collect();
        let head = if want.is_empty() {
            "Several Apple devices were found".to_string()
        } else {
            format!("Several devices match \"{want}\"")
        };
        die(format!("{head}. Choose one:{lines}"));
    }
    // Strongest signal first, the order --list reports in.
    matches[0].mac.clone()
}

/// Ask for names until the one wanted answers, keeping answers across
/// passes but finishing each pass before choosing: another device may have
/// the same name. Every wait is bounded by OMDROP_NAME_WAIT, including a
/// lookup that closes its output but stays alive; each pass runs in its own
/// session, so a cancel or the deadline stops its probes and Bluetooth
/// advertising together (TERM, then KILL two seconds later).
fn find_by_name(want: &str, shown: &str) -> (String, i32) {
    let c = ctx();
    let start = Instant::now();
    let deadline = start + Duration::from_secs(c.name_wait);
    let mut order: Vec<String> = Vec::new();
    let mut row_of: HashMap<String, String> = HashMap::new();
    let mut said: HashMap<String, ()> = HashMap::new();
    let mut found = false;
    let mut note_at = start;
    trap_signals();
    outln!("Looking for \"{shown}\" nearby (up to {}s)...", c.name_wait);
    let secs_left = || {
        deadline
            .saturating_duration_since(Instant::now())
            .as_secs_f64()
            .ceil() as u64
    };
    loop {
        if Instant::now() >= deadline {
            break;
        }
        let mut other = String::new();
        let pass = name_pass(deadline, &mut |line| {
            if let Some(row) = parse_row(line) {
                // Keep an earlier answer if a later pass gets no response.
                if !(row_of.contains_key(&row.mac) && row.name == "(no response)") {
                    if !row_of.contains_key(&row.mac) {
                        order.push(row.mac.clone());
                    }
                    row_of.insert(row.mac.clone(), line.to_string());
                }
                if !placeholder(&row.name) {
                    crate::names::store(std::slice::from_ref(&row));
                    if said.insert(row.mac.clone(), ()).is_none() {
                        outln!("Heard from {}.", row.name);
                    }
                    if row.name.to_lowercase().contains(want) {
                        found = true;
                    }
                }
            } else {
                other.push_str(line);
                other.push('\n');
            }
        });
        let rc = match pass {
            Pass::Done(rc) => rc,
            Pass::TimedOut => {
                // A truncated pass cannot establish uniqueness, even if a
                // match arrived.
                let answers: String = if order.is_empty() {
                    "  ".to_string()
                } else {
                    order
                        .iter()
                        .map(|m| format!("  {}", row_of[m]))
                        .collect::<Vec<_>>()
                        .join("\n")
                };
                die(format!(
                    "Name lookup did not finish within {} seconds; nothing was sent. Open AirDrop on \"{shown}\" and try again.\n{other}Answers so far:\n{answers}",
                    c.name_wait
                ));
            }
        };
        if rc != 0 && rc != 1 {
            die(other.strip_suffix('\n').unwrap_or(&other));
        }
        if found {
            break;
        }
        if Instant::now() >= deadline {
            break;
        }
        if Instant::now() >= note_at {
            outln!(
                "No \"{shown}\" yet (devices heard: {}, named: {}). Still looking, {}s left...",
                row_of.len(),
                said.len(),
                secs_left()
            );
            note_at = Instant::now() + Duration::from_secs(15);
        }
        // A fast empty pass must not spin, or sleep past the budget.
        nap_until((Instant::now() + Duration::from_secs(3)).min(deadline));
    }
    untrap_signals();
    let listing = order
        .iter()
        .map(|m| row_of[m].clone())
        .collect::<Vec<_>>()
        .join("\n");
    let rc = if order.is_empty() { 1 } else { 0 };
    (listing, rc)
}

enum Pass {
    Done(i32),
    TimedOut,
}

/// One lookup: probe whether the sender can stream names (so they arrive
/// as each device answers), then `--list --names [--stream]`, its stdout
/// and stderr together, line by line, all before the deadline.
fn name_pass(deadline: Instant, on_line: &mut dyn FnMut(&str)) -> Pass {
    let mut probe = sender_cmd();
    probe.arg("--help");
    let help = match run_bounded(&mut probe, deadline, &mut |_| {}) {
        Bounded::Done(_, out) => out,
        Bounded::TimedOut => return Pass::TimedOut,
        Bounded::Failed(_) => String::new(),
    };
    let mut lookup = sender_cmd();
    lookup.args(["--list", "--names"]);
    if help.contains("--stream") {
        lookup.arg("--stream");
    }
    match run_bounded(&mut lookup, deadline, on_line) {
        Bounded::Done(rc, _) => Pass::Done(rc),
        Bounded::TimedOut => Pass::TimedOut,
        Bounded::Failed(rc) => Pass::Done(rc),
    }
}

enum Bounded {
    Done(i32, String),
    TimedOut,
    Failed(i32),
}

/// Run in a session of its own with stdout and stderr on one pipe, handing
/// each line over as it comes. At the deadline, or on a cancel, the whole
/// session goes.
fn run_bounded(cmd: &mut Command, deadline: Instant, on_line: &mut dyn FnMut(&str)) -> Bounded {
    let Ok((read, write)) = pipe() else {
        return Bounded::Failed(126);
    };
    let Ok(write2) = write.try_clone() else {
        return Bounded::Failed(126);
    };
    cmd.stdin(Stdio::null())
        .stdout(Stdio::from(write))
        .stderr(Stdio::from(write2));
    let spawned = spawn_session(cmd);
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
    let mut child: Child = match spawned {
        Ok(c) => c,
        Err(e) => {
            on_line(&format!(
                "omdrop: {}: {e}",
                cmd.get_program().to_string_lossy()
            ));
            return Bounded::Failed(if e.kind() == std::io::ErrorKind::NotFound {
                127
            } else {
                126
            });
        }
    };
    let mut reader = LineReader::new(read);
    let mut all = String::new();
    loop {
        match reader.read_line(Some(deadline)) {
            Read1::Signal => cancelled(Some(&mut child)),
            Read1::Line(l) => {
                let line = String::from_utf8_lossy(&l).into_owned();
                on_line(&line);
                all.push_str(&line);
                all.push('\n');
            }
            Read1::Eof => break,
            Read1::Timeout => {
                stop_group(&mut child);
                return Bounded::TimedOut;
            }
        }
    }
    match wait_cancellable(&mut child, Some(deadline)) {
        Some(rc) => Bounded::Done(rc, all),
        None => {
            stop_group(&mut child);
            Bounded::TimedOut
        }
    }
}

#[derive(Serialize)]
struct PeerJson<'a> {
    mac: &'a str,
    rssi: Option<i64>,
    name: Option<&'a str>,
}

/// The listing as JSON for the panel. The placeholders a lookup prints for
/// a peer that did not answer are not names, so they become null rather
/// than labels on the radar.
fn peer_json(row: &Row) -> String {
    let name = row.name.trim();
    py_json(&PeerJson {
        mac: &row.mac,
        rssi: if row.rssi == "?" {
            None
        } else {
            row.rssi.parse().ok()
        },
        name: (!placeholder(name)).then_some(name),
    })
}

pub fn peers_json(listing: &str) -> String {
    let rows: Vec<Row> = listing.lines().filter_map(parse_row).collect();
    let items: Vec<String> = rows.iter().map(peer_json).collect();
    format!("[{}]", items.join(", "))
}

pub fn cmd_peers(args: &[String]) -> i32 {
    // -n is opt-in because asking a peer its name means connecting to it,
    // which shows this machine to every device listed, and raises a BLE
    // advert with this account's contact hashes so a Contacts Only device
    // answers at all. --no-wake asks without that broadcast.
    let (mut names, mut wake, mut json, mut stream) = (false, false, false, false);
    for a in args {
        match a.as_str() {
            "-n" | "--names" => names = true,
            "--no-wake" => wake = true,
            "--json" => json = true,
            "--stream" => stream = true,
            _ => die("usage: omdrop peers [-n|--names] [--no-wake] [--json] [--stream]"),
        }
    }
    if stream && !(json && names) {
        die("omdrop peers: --stream is for the panel and needs --json -n");
    }
    require_sender();
    if names && !sender_help_has("--names") {
        die(format!(
            "Looking up peer names needs a newer {}. {}",
            radio_pkg(),
            radio_update()
        ));
    }
    // One named lookup at a time per user, whichever program asks: overlapping
    // ones piled up adverts and connection bursts until names stopped resolving.
    let turn = match names.then(crate::names::lookup) {
        Some(Lookup::Running(watch)) if stream => return follow_stream(&watch),
        Some(Lookup::Running(watch)) => {
            let (rc, out) = after_lookup(&watch, !json);
            return print_peers(rc, &out, json, names);
        }
        Some(Lookup::Ours(turn)) => Some(turn),
        None => None,
    };
    let mut cmd = sender_cmd();
    cmd.arg("--list");
    if names {
        cmd.arg("--names");
    }
    if wake {
        cmd.arg("--no-wake");
    }
    // --stream: one JSON object per peer, the moment that peer answers, so
    // the panel shows a name seconds after it arrives. Still its own process
    // group, so stopping this command stops the sender and its advert. A
    // driver too old for --stream gives the same lines, all at the end.
    if stream {
        if sender_help_has("--stream") {
            cmd.arg("--stream");
        }
        return peers_stream(&mut cmd);
    }
    // Naming takes fifteen to twenty seconds (measured 2026-09-21), and
    // silence that long reads as a hang. The panel draws its own progress.
    let spin = names && !json;
    trap_signals();
    if spin {
        crate::proc::spinner_start("Asking nearby devices for their names");
    }
    let (rc, out) = listing(&mut cmd);
    if spin {
        crate::proc::spinner_restore_tty();
    }
    untrap_signals();
    if names {
        let rows: Vec<Row> = out.lines().filter_map(parse_row).collect();
        crate::names::store(&rows);
    }
    drop(turn);
    print_peers(rc, &out, json, names)
}

/// A listing as `peers` prints it, where it has a name column (JSON, `-n`)
/// with each row that has no name given the one learned for its address.
fn print_peers(rc: i32, out: &str, json: bool, names: bool) -> i32 {
    let out = if rc == 0 && (json || names) {
        crate::names::load().fill_listing(out)
    } else {
        out.to_string()
    };
    if json {
        // An empty room is still an answer the panel can draw: `[]` on
        // stdout, and the same exit status and sentence as text on stderr.
        match rc {
            0 => {
                outln!("{}", peers_json(&out));
                return 0;
            }
            1 => outln!("[]"),
            _ => die(&out),
        }
    }
    if rc == 1 {
        // The RADIO, not the receiver, decides: it is the window that runs
        // the peer watcher which fills this table.
        let (_, st) = crate::proc::capture(&ctx().discoverable, &["status", "--json"]);
        if !String::from_utf8_lossy(&st).contains("\"visible\":true") {
            die("Omdrop is currently OFF. Turn it on to see peers.");
        }
        // A window IS open: nobody is there yet. Peers appear as they
        // transmit, which for a Mac or iPhone means opening its share sheet.
        die(
            "No devices found yet. Open the AirDrop sheet on the device you want to see, then run this again.",
        );
    }
    outln!("{out}");
    rc
}

/// How often a follower of another program's lookup looks for news.
const FOLLOW_POLL: Duration = Duration::from_millis(200);

/// `peers -n` while another program's lookup runs: wait for it, at most
/// OMDROP_NAME_WAIT, then answer from the table and the names learned.
fn after_lookup(watch: &Watch, spin: bool) -> (i32, String) {
    trap_signals();
    if spin {
        crate::proc::spinner_start("Waiting for the name lookup already running");
    }
    let deadline = Instant::now() + Duration::from_secs(ctx().name_wait);
    while watch.running() && Instant::now() < deadline {
        nap_until((Instant::now() + FOLLOW_POLL).min(deadline));
    }
    let listed = passive_listing();
    if spin {
        crate::proc::spinner_restore_tty();
    }
    untrap_signals();
    listed
}

/// `peers -n --json --stream` while another program's lookup runs: the names
/// learned for the table's devices, then each one that lookup stores, until it
/// ends or OMDROP_NAME_WAIT passes.
fn follow_stream(watch: &Watch) -> i32 {
    trap_signals();
    let deadline = Instant::now() + Duration::from_secs(ctx().name_wait);
    let since = crate::names::now();
    let (rc, listed) = passive_listing();
    if rc != 0 && rc != 1 {
        untrap_signals();
        return rc;
    }
    let mut table: Vec<Row> = listed.lines().filter_map(parse_row).collect();
    let mut shown: HashMap<String, String> = HashMap::new();
    loop {
        // Looked at before the names are read: a lookup stores its last name
        // before it lets go of the lock.
        let ended = !watch.running() || Instant::now() >= deadline;
        let names = crate::names::load();
        let mut fresh: Vec<(String, String)> = Vec::new();
        let known = table
            .iter()
            .filter_map(|r| names.get(&r.mac).map(|n| (r.mac.as_str(), n)));
        for (mac, name) in known.chain(names.since(since)) {
            if shown.get(mac).map(String::as_str) != Some(name)
                && !fresh.iter().any(|(m, _)| m == mac)
            {
                fresh.push((mac.to_string(), name.to_string()));
            }
        }
        // A device heard since the table was read: read it again for its row.
        if fresh
            .iter()
            .any(|(mac, _)| !table.iter().any(|r| r.mac == *mac))
            && let (0, listed) = passive_listing()
        {
            table = listed.lines().filter_map(parse_row).collect();
        }
        for (mac, name) in fresh {
            if let Some(r) = table.iter().find(|r| r.mac == mac) {
                let row = Row {
                    mac: r.mac.clone(),
                    rssi: r.rssi.clone(),
                    name: name.clone(),
                };
                if !emit(&row) {
                    crate::util::exit(141);
                }
            }
            shown.insert(mac, name);
        }
        if ended {
            break;
        }
        nap_until(Instant::now() + FOLLOW_POLL);
    }
    untrap_signals();
    rc
}

fn peers_stream(cmd: &mut Command) -> i32 {
    trap_signals();
    // Learned names for the table's devices first: a program reading only this
    // stream shows them at once. An unreadable table is the lookup's to report.
    let mut names = crate::names::load();
    let mut table = sender_cmd();
    table.arg("--list").stderr(Stdio::null());
    if let (0, listed) = listing(&mut table) {
        for mut row in listed.lines().filter_map(parse_row) {
            if names.fill(&mut row) && !emit(&row) {
                crate::util::exit(141);
            }
        }
    }
    let Ok((read, write)) = pipe() else {
        die("omdrop could not create a pipe.");
    };
    cmd.stdout(Stdio::from(write));
    let spawned = spawn_group(cmd);
    cmd.stdout(Stdio::null());
    let mut child = match spawned {
        Ok(c) => c,
        Err(e) => {
            untrap_signals();
            return crate::proc::spawn_error(cmd, &e);
        }
    };
    let mut reader = LineReader::new(read);
    loop {
        match reader.read_line(None) {
            Read1::Signal => cancelled(Some(&mut child)),
            Read1::Line(l) => {
                if let Some(mut row) = parse_row(&String::from_utf8_lossy(&l)) {
                    if names.learn(&row, crate::names::now()) {
                        crate::names::store(std::slice::from_ref(&row));
                    } else {
                        names.fill(&mut row);
                    }
                    // Nobody reading any more (the panel died without a
                    // signal): stop the lookup and its advert now, as the
                    // bash pipeline's SIGPIPE did, not at the lookup's end.
                    if !emit(&row) {
                        stop_group(&mut child);
                        crate::util::exit(141);
                    }
                }
            }
            _ => break,
        }
    }
    let rc = wait_cancellable(&mut child, None).unwrap_or(1);
    untrap_signals();
    rc
}

/// One row of a stream, flushed at once; false when nobody reads any more.
fn emit(row: &Row) -> bool {
    use std::io::Write;
    let line = format!("{}\n", peer_json(row));
    let mut out = std::io::stdout();
    out.write_all(line.as_bytes())
        .and_then(|()| out.flush())
        .is_ok()
}

/// Sleep until `until`, unless a signal arrives first: then "Cancelled.".
fn nap_until(until: Instant) {
    while Instant::now() < until {
        if crate::proc::caught().is_some() {
            cancelled(None);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The radio's table alone: `--list`, which transmits nothing.
fn passive_listing() -> (i32, String) {
    let mut cmd = sender_cmd();
    cmd.arg("--list");
    listing(&mut cmd)
}

/// `cmd`'s exit status and its stdout, read once it has finished; the
/// caller has trapped the signals. The panel ends a named lookup every time
/// its section closes, and a bare kill of the old script left the sender and
/// its advert running, piling up beside the next lookup. So `cmd` runs as
/// its own process group, which a cancel stops whole, and writes to a file.
fn listing(cmd: &mut Command) -> (i32, String) {
    let tmp = anonymous_file().unwrap_or_else(|| die("could not make a temporary file"));
    let Ok(out_fd) = tmp.try_clone() else {
        die("could not make a temporary file");
    };
    cmd.stdout(Stdio::from(out_fd));
    let rc = match spawn_group(cmd) {
        Ok(mut child) => wait_cancellable(&mut child, None).unwrap_or(1),
        Err(e) => crate::proc::spawn_error(cmd, &e),
    };
    let out = read_all(tmp);
    (rc, crate::util::strip_trailing_newlines(&out).to_string())
}

/// A file only we can reach: created in the runtime directory and unlinked
/// at once, so nothing is left behind however we end.
fn anonymous_file() -> Option<std::fs::File> {
    let dir = crate::util::env_nonempty("XDG_RUNTIME_DIR").unwrap_or_else(|| "/tmp".to_string());
    let (path, file) =
        crate::util::create_unique(Path::new(&dir), "omdrop-peers.", "", 0o600).ok()?;
    let _ = std::fs::remove_file(path);
    Some(file)
}

fn read_all(mut f: std::fs::File) -> String {
    use std::io::{Read, Seek};
    let mut s = Vec::new();
    let _ = f.seek(std::io::SeekFrom::Start(0));
    let _ = f.read_to_end(&mut s);
    String::from_utf8_lossy(&s).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_are_read_as_the_bash_read_them() {
        let r = parse_row("e2:9d:03:6c:58:23   -47 dBm  [fe80::e09d:3ff:fe6c:5823%awdl0]:8770")
            .unwrap();
        assert_eq!(
            (r.mac.as_str(), r.rssi.as_str(), r.name.as_str()),
            ("e2:9d:03:6c:58:23", "-47", "")
        );
        let r = parse_row("b2:c4:98:5e:e6:be     ? dBm  [fe80::b0c4%awdl0]:8770  (no response)")
            .unwrap();
        assert_eq!((r.rssi.as_str(), r.name.as_str()), ("?", "(no response)"));
        let r = parse_row("02:00:00:00:00:01  -40 dBm  [fe80::1%awdl0]:8770  Studio Mac ").unwrap();
        assert_eq!(r.name, "Studio Mac ");
        for bad in [
            "E2:9D:03:6C:58:23  -47 dBm  x",
            "e2:9d:03:6c:58:23-47 dBm  x",
            "e2:9d:03:6c:58:23  -47dBm  x",
            "e2:9d:03:6c:58:23  -47 dBm",
            "could not read",
        ] {
            assert!(parse_row(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn peers_json_matches_what_python_printed() {
        let listing = "22:8b:38:31:89:4e   -34 dBm  [fe80::208b%awdl0]:8770  hume\nb2:c4:98:5e:e6:be     ? dBm  [fe80::b0c4%awdl0]:8770  (no response)\nf2:f2:ee:c4:5a:f7     ? dBm  [fe80::f0f2%awdl0]:8770  Brent's iPhone\nnoise";
        assert_eq!(
            peers_json(listing),
            r#"[{"mac": "22:8b:38:31:89:4e", "rssi": -34, "name": "hume"}, {"mac": "b2:c4:98:5e:e6:be", "rssi": null, "name": null}, {"mac": "f2:f2:ee:c4:5a:f7", "rssi": null, "name": "Brent's iPhone"}]"#
        );
        assert_eq!(peers_json(""), "[]");
    }

    #[test]
    fn upload_progress_becomes_owlys_byte_step_and_no_sentence() {
        let line = "2026-11-12 01:00:00,000 INFO send: +  2.50s UPLOAD progress 65536/52428800";
        assert_eq!(progress(line), Some("\r65536 / 52428800 bytes".into()));
        assert_eq!(narrate(line), None, "a step is not a sentence");
        assert_eq!(
            progress("+2.72s UPLOAD photo.jpg -> ok (2493 B, 0.62s)"),
            None
        );
        assert_eq!(progress("+1.00s UPLOAD progress lots/52428800"), None);
    }

    #[test]
    fn the_log_becomes_four_sentences() {
        let n = |l: &str| narrate(l);
        assert_eq!(
            n("+0.41s FOUND 0e9d 'hume' at [fe80::1]:8770; asking"),
            Some((false, "Asking them to accept it...".into()))
        );
        assert_eq!(
            n("+2.10s ASK -> accepted (1.69s)"),
            Some((false, "They accepted. Sending...".into()))
        );
        assert_eq!(
            n("+4.02s ASK -> declined (3.61s)"),
            Some((true, "They declined it.".into()))
        );
        assert_eq!(
            n("x ASK failed: timed out"),
            Some((true, "They never answered: timed out".into()))
        );
        assert_eq!(
            n("x UPLOAD failed: reset"),
            Some((true, "The transfer failed: reset".into()))
        );
        assert_eq!(
            n("x UPLOAD photo.jpg -> FAILED"),
            Some((true, "The transfer failed.".into()))
        );
        assert_eq!(
            n("+2.72s UPLOAD photo.jpg -> ok (2493 B, 0.62s)"),
            Some((false, "Sent photo.jpg (2493 B, 0.62s)".into()))
        );
        assert_eq!(
            n("+1.21s LINK https://example.com/ -> ok"),
            Some((false, "Sent https://example.com/".into()))
        );
        assert_eq!(n("DEBUG something else"), None);
    }
}
