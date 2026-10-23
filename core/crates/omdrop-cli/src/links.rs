//! Arrivals and links: `watch` (follow the receiver's log), `handle`
//! (copy and announce), `act`, `open-link`, the double-click handler for
//! received links, and the agent skill.
//!
//! A received link is a URL chosen by whoever is standing nearby, and while
//! discoverable to Everyone that is a one-tap phishing delivery. The receiver
//! stores links inert; nothing here opens one on its own.

use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime};

use crate::config::effective_dir;
use crate::ctx::{UNIT, ctx};
use crate::proc::{code_of, run_bounded, run_quiet, timeout_duration};
use crate::util::{
    basename, create_unique, die, dirname, env_nonempty, glob_match, have, home, is_symlink,
    lexists, mkdir_private, tildify,
};

/// These arrive from whoever is nearby; a real one is a few hundred bytes.
const LINK_MAX: u64 = 65536;

/// The URL inside an Apple .webloc or a Windows .url shortcut, unchecked.
/// `None` when the file is not one (or is unreadable or too big); an empty
/// string when it is one with no URL in it.
pub fn link_url(f: &Path) -> Option<String> {
    let meta = std::fs::metadata(f).ok()?;
    if !meta.is_file() || meta.len() > LINK_MAX || !crate::util::is_readable(f) {
        return None;
    }
    let lower = f.as_os_str().to_string_lossy().to_lowercase();
    let data = std::fs::read(f).ok()?;
    if lower.ends_with(".url") {
        Some(url_file_target(&data))
    } else if lower.ends_with(".webloc") {
        webloc_target(&data)
    } else {
        None
    }
}

/// .url: the first URL= in the [InternetShortcut] section, CR stripped,
/// because a Windows-written file has CRLF lines and a URL= elsewhere is not
/// the link.
fn url_file_target(data: &[u8]) -> String {
    let text = String::from_utf8_lossy(data);
    let mut in_section = false;
    for raw in text.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        let lead = line.trim_start_matches([' ', '\t']);
        if lead.starts_with('[') {
            let s: String = line
                .to_ascii_lowercase()
                .chars()
                .filter(|c| *c != ' ' && *c != '\t')
                .collect();
            in_section = s == "[internetshortcut]";
            continue;
        }
        if in_section {
            let lower = lead.to_ascii_lowercase();
            if let Some(after) = lower.strip_prefix("url")
                && after.trim_start_matches([' ', '\t']).starts_with('=')
            {
                let eq = line.find('=').map_or(line.len(), |i| i + 1);
                return line[eq..]
                    .trim_start_matches([' ', '\t'])
                    .trim_end_matches([' ', '\t'])
                    .to_string();
            }
        }
    }
    String::new()
}

/// .webloc: the URL key of a property list, XML or binary -- macOS writes both.
/// Parsed under safeplist's limits: the file came from whoever is nearby, and
/// 64 KB of binary plist can reference one object until it decodes to more
/// memory than the machine has.
fn webloc_target(data: &[u8]) -> Option<String> {
    let value = omdrop_identity::safeplist::parse(data).ok()?;
    let dict = value.as_dictionary()?;
    Some(match dict.get("URL") {
        Some(plist::Value::String(s)) => s.trim().to_string(),
        _ => String::new(),
    })
}

/// Whether a URL is a web page, the only kind Omdrop opens. A received link
/// can name file://, smb://, or an app's custom scheme, so everything else
/// is refused before anything launches.
pub fn web_url(u: &str) -> bool {
    let l = u.to_lowercase();
    if !(l.starts_with("http://") || l.starts_with("https://")) {
        return false;
    }
    if u.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    let rest = l.split_once("://").map_or("", |(_, r)| r);
    !rest.is_empty() && !rest.starts_with('/')
}

/// The web link in a link file. Every caller that opens or copies a link
/// goes through here, so there is one gate.
pub fn link_target(f: &Path) -> Option<String> {
    link_url(f).filter(|u| web_url(u))
}

pub fn is_link_file(f: &OsStr) -> bool {
    let l = f.to_string_lossy().to_lowercase();
    l.ends_with(".url") || l.ends_with(".webloc")
}

/// Launch a GUI app so it OUTLIVES us. The watcher runs as a transient
/// service whose cgroup dies with it, taking any setsid child along;
/// uwsm-app puts the app in its own unit, as the rest of Omarchy does.
/// Synchronously: uwsm-app returns once the app has its own unit, and we
/// must still be alive at that moment.
fn launch(args: &[&OsStr], stdin: Option<Stdin>, cwd: Option<&Path>) {
    let shown = args
        .iter()
        .map(|a| a.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");
    let (prog, mut full): (&str, Vec<&OsStr>) = if have("uwsm-app") {
        ("uwsm-app", vec![OsStr::new("--")])
    } else {
        (
            "systemd-run",
            vec![
                OsStr::new("--user"),
                OsStr::new("--quiet"),
                OsStr::new("--collect"),
            ],
        )
    };
    full.extend(args);
    let mut cmd = Command::new(prog);
    cmd.args(&full);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let ok = match stdin {
        None => cmd.status().map(code_of).unwrap_or(127) == 0,
        Some(Stdin::File(path)) => match std::fs::File::open(path) {
            Ok(f) => cmd.stdin(f).status().map(code_of).unwrap_or(127) == 0,
            Err(e) => {
                errln!("omdrop: {}: {e}", path.display());
                false
            }
        },
        Some(Stdin::Bytes(bytes)) => match cmd.stdin(Stdio::piped()).spawn() {
            Ok(mut child) => {
                if let Some(mut pipe) = child.stdin.take() {
                    let _ = pipe.write_all(&bytes);
                }
                child.wait().map(code_of).unwrap_or(1) == 0
            }
            Err(_) => false,
        },
    };
    if !ok {
        if prog == "uwsm-app" {
            errln!("omdrop: uwsm-app could not launch: {shown}");
        } else {
            errln!("omdrop: could not launch: {shown}");
        }
    }
}

enum Stdin<'a> {
    File(&'a Path),
    Bytes(Vec<u8>),
}

/// `open-link FILE`: open a link file's web page in the browser -- the one
/// entry point for the notification's click and a double-click in the file
/// manager. A link that is not a web page is refused with a notification,
/// because whoever double-clicked is looking at the file manager.
pub fn cmd_open_link(args: &[OsString]) -> i32 {
    let Some(f) = args.first().filter(|a| !a.is_empty()) else {
        die("usage: omdrop open-link FILE");
    };
    open_link(Path::new(f))
}

fn open_link(f: &Path) -> i32 {
    if let Some(url) = link_target(f) {
        return run_quiet("omarchy-launch-browser", &[url]);
    }
    let why = match link_url(f) {
        Some(raw) if raw.contains(':') => format!(
            "It points to a {}: address, and Omdrop opens only web links.",
            raw.split(':').next().unwrap_or("")
        ),
        _ => "There is no web link in it.".to_string(),
    };
    let title = format!("Can't open {}", basename(f.as_os_str()).to_string_lossy());
    if run_quiet("omarchy-notification-send", &[title.as_str(), why.as_str()]) != 0 {
        errln!("omdrop: can't open {}: {why}", f.display());
    }
    1
}

fn act_open(f: &Path) -> i32 {
    if is_link_file(f.as_os_str()) {
        return open_link(f);
    }
    if has_default_app(f) {
        launch(&[OsStr::new("xdg-open"), f.as_os_str()], None, None);
    } else {
        reveal_in_files(f);
    }
    0
}

/// Whether xdg-open has an app registered for the file's type. Without one it
/// falls back to the browser: imv registers image/heif but not image/heic, and
/// Omarchy's defaults register nothing for it, so an iPhone photo opened Chrome.
/// Without xdg-mime there is nothing to ask, and xdg-open keeps the file.
fn has_default_app(f: &Path) -> bool {
    if !have("xdg-mime") {
        return true;
    }
    let ask = |args: &[&OsStr]| {
        let (_, out) = crate::proc::capture("xdg-mime", args);
        crate::util::strip_trailing_newlines_bytes(&out).to_vec()
    };
    let kind = ask(&[OsStr::new("query"), OsStr::new("filetype"), f.as_os_str()]);
    !kind.is_empty()
        && !ask(&[
            OsStr::new("query"),
            OsStr::new("default"),
            OsStr::from_bytes(&kind),
        ])
        .is_empty()
}

/// Show a received file in the file manager with it selected: the click's
/// fallback when no app is registered for the file. Nautilus is Omarchy's file
/// manager; anything else gets the folder through xdg-open, which never hands a
/// file to the browser.
fn reveal_in_files(f: &Path) {
    if have("nautilus") {
        launch(
            &[
                OsStr::new("nautilus"),
                OsStr::new("--select"),
                f.as_os_str(),
            ],
            None,
            None,
        );
    } else {
        let dir = dirname(f.as_os_str());
        launch(&[OsStr::new("xdg-open"), dir.as_os_str()], None, None);
    }
}

/// What to do with a file once the person has asked: `act open` is what the
/// notification fires when clicked; shell and browse are for the terminal.
pub fn cmd_act(args: &[OsString]) -> i32 {
    let Some(what) = args.first().filter(|a| !a.is_empty()) else {
        die("usage: omdrop act open|shell|browse FILE");
    };
    let Some(f) = args.get(1).filter(|a| !a.is_empty()) else {
        die("usage: omdrop act open|shell|browse FILE");
    };
    let f = Path::new(f);
    let dir = PathBuf::from(dirname(f.as_os_str()));
    match what.to_str().unwrap_or("") {
        "open" => act_open(f),
        "shell" => {
            if !dir.is_dir() {
                errln!("omdrop: cd: {}: No such file or directory", dir.display());
                return 1;
            }
            let (_, term) = crate::proc::capture_cmd(
                Command::new("omarchy-default-terminal").current_dir(&dir),
            );
            let term =
                OsString::from_vec(crate::util::strip_trailing_newlines_bytes(&term).to_vec());
            launch(&[term.as_os_str()], None, Some(&dir));
            0
        }
        "browse" => {
            launch(&[OsStr::new("xdg-open"), dir.as_os_str()], None, None);
            0
        }
        other => die(format!("act {other}: one of open, shell, browse")),
    }
}

fn is_image(lower: &str) -> Option<&'static str> {
    [
        (".png", "image/png"),
        (".jpg", "image/jpeg"),
        (".jpeg", "image/jpeg"),
        (".gif", "image/gif"),
        (".webp", "image/webp"),
    ]
    .into_iter()
    .find(|(ext, _)| lower.ends_with(ext))
    .map(|(_, t)| t)
}

/// Seconds `heif-convert` gets to decode an arrival before it is killed and
/// the path is copied instead. A 12 MP iPhone HEIC decodes in about a second;
/// the input can come from any nearby sender in Everyone mode, so a file
/// crafted to decode slowly must not hold the watcher.
const HEIF_DECODE_SECS: u64 = 10;

/// The memory each arrival's `handle` unit may use, decodes included, as the
/// plugin's bash `omdrop` sets it.
const HANDLE_MEMORY_MAX: &str = "MemoryMax=512M";

/// HEIC, HEIF and AVIF: what an iPhone sends since the receiver asks for
/// original-format photos (#62), and what few applications can paste.
fn is_heif(lower: &str) -> bool {
    [".heic", ".heif", ".avif"]
        .iter()
        .any(|e| lower.ends_with(e))
}

/// The lock every decode of an arrival holds, `$XDG_RUNTIME_DIR/omdrop/
/// decode.lock`, exclusive, waited for: one decode at a time per user. A
/// HEIC is decoded at the size it declares, whatever its file size, and a
/// sender in Everyone mode can send hundreds in one transfer, each arrival
/// with its own `handle` running at once. The plugin's bash `omdrop` takes
/// the same lock with flock(1), so decodes from both stacks queue together.
/// Each decode is bounded by its timeout, so the wait is too. `None` when the
/// lock cannot be taken: then nothing is decoded.
fn decode_lock() -> Option<std::fs::File> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let dir = ctx().state_dir();
    mkdir_private(&dir).ok()?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(dir.join("decode.lock"))
        .ok()?;
    loop {
        // SAFETY: flock on a descriptor `file` owns; released when it closes.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
            return Some(file);
        }
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return None;
        }
    }
}

/// Decode `f` to a JPEG in a private directory of its own under the runtime
/// directory. `None` on any failure, including a missing `heif-convert`; the
/// caller removes the directory, which is returned with the JPEG either way
/// once it exists. heif-convert names extra outputs (`out-1.jpg` for a file
/// with several top-level images) beside its target, so only the exact
/// target counts and the whole directory goes afterwards.
fn heif_to_jpeg(f: &Path) -> Option<(PathBuf, PathBuf)> {
    if !have("heif-convert") {
        return None;
    }
    let _decoding = decode_lock()?;
    let base = ctx().runtime.join("omdrop");
    std::fs::create_dir_all(&base).ok()?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let dir = base.join(format!("clip-{}-{nanos}", std::process::id()));
    std::fs::DirBuilder::new().mode(0o700).create(&dir).ok()?;
    let out = dir.join("arrival.jpg");
    let mut cmd = Command::new("heif-convert");
    cmd.args([OsStr::new("--quiet"), OsStr::new("-q"), OsStr::new("90")])
        .arg(f)
        .arg(&out)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let limit = Some(Duration::from_secs(HEIF_DECODE_SECS));
    if run_bounded(&mut cmd, limit, Duration::from_secs(2)) && non_empty_file(&out) {
        Some((dir, out))
    } else {
        let _ = std::fs::remove_dir_all(&dir);
        None
    }
}

/// `[[ -s FILE ]]`: it exists and has something in it.
fn non_empty_file(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.len() > 0)
}

/// Previews live in the runtime dir: RAM, private to the user, and gone at
/// logout, so they never become a second copy of every photo received. Only
/// the last PREVIEW_KEEP stay -- enough for the toasts of a burst of photos
/// to still find their image.
const PREVIEW_KEEP: usize = 10;
/// heif-convert decodes at full size -- 4032x3024 for a 12 MP photo -- and
/// the toast shows a few hundred pixels.
const PREVIEW_SIZE: &str = "512x512>";
/// A `working.*` this old was left behind by a decode that was killed.
const PREVIEW_STALE: Duration = Duration::from_secs(5 * 60);
/// `timeout -k 1`: how long a decode past its limit gets between TERM and KILL.
const PREVIEW_GRACE: Duration = Duration::from_secs(1);

/// In Everyone mode the file comes from anyone nearby and is decoded without
/// a click, so each step of a preview gets OMDROP_PREVIEW_TIMEOUT, timeout(1)'s
/// DURATION, default 10 s. `None`: not a duration, which timeout refuses.
fn preview_timeout() -> Option<Option<Duration>> {
    timeout_duration(&env_nonempty("OMDROP_PREVIEW_TIMEOUT").unwrap_or_else(|| "10".to_string()))
}

/// A small JPEG preview for formats the notification daemon cannot decode
/// (HEIC from an iPhone): its path, or `None` when none is possible. A failed
/// or timed-out decode only costs the toast its thumbnail. The file is
/// untrusted, so it reaches heif-convert as an argument, never through a shell.
fn heic_preview(f: &Path) -> Option<PathBuf> {
    if !have("heif-convert") {
        return None;
    }
    let limit = preview_timeout()?;
    let dir = ctx().state_dir().join("previews");
    mkdir_private(&dir).ok()?;
    // The decode and the shrink run under the decode lock; the rest does not.
    let decoding = decode_lock()?;
    // A unique name: IMG_1.heic and IMG_1.avif, or two arrivals with the same
    // name, each keep their own preview. Arrivals are handled in parallel, so
    // a preview is decoded and shrunk under working.*, and becomes preview.*
    // -- the only name pruning looks at -- once it is complete.
    let (work, file) = create_unique(&dir, "working.", ".jpg", 0o600).ok()?;
    drop(file);
    let id = work
        .file_name()
        .and_then(OsStr::to_str)
        .and_then(|n| n.strip_prefix("working."))
        .and_then(|n| n.strip_suffix(".jpg"))
        .unwrap_or_default()
        .to_string();
    let done = dir.join(format!("preview.{id}.jpg"));
    let mut cmd = Command::new("heif-convert");
    cmd.args([OsStr::new("-q"), OsStr::new("80")])
        .arg(f)
        .arg(&work)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if !(run_bounded(&mut cmd, limit, PREVIEW_GRACE) && non_empty_file(&work)) {
        let _ = std::fs::remove_file(&work);
        // heif-convert names the images of a multi-image file out-1.jpg, out-2.jpg.
        let extra = format!("working.{id}-");
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.as_bytes();
                if name.starts_with(extra.as_bytes()) && name.ends_with(b".jpg") {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
        return None;
    }
    shrink_preview(&work, limit);
    drop(decoding);
    // Pruning goes by when a preview was finished. A shrink that failed or
    // timed out leaves the decode's older time, and the newer previews of a
    // burst would prune this one before its toast could show it.
    let _ = std::fs::File::options()
        .write(true)
        .open(&work)
        .and_then(|f| f.set_modified(SystemTime::now()));
    if std::fs::rename(&work, &done).is_err() {
        let _ = std::fs::remove_file(&work);
        return None;
    }
    prune_previews(&dir);
    Some(done)
}

/// Scale a preview down when ImageMagick is present; without it the
/// full-size preview stays, still in RAM and still pruned.
fn shrink_preview(work: &Path, limit: Option<Duration>) {
    if !have("magick") {
        return;
    }
    let mut part = work.as_os_str().to_owned();
    part.push(".part");
    let part = PathBuf::from(part);
    let mut target = OsString::from("jpg:");
    target.push(&part);
    let mut cmd = Command::new("magick");
    cmd.arg(work)
        .args(["-thumbnail", PREVIEW_SIZE, "-quality", "80"])
        .arg(&target)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if !(run_bounded(&mut cmd, limit, PREVIEW_GRACE)
        && non_empty_file(&part)
        && std::fs::rename(&part, work).is_ok())
    {
        let _ = std::fs::remove_file(&part);
    }
}

/// Keep the newest PREVIEW_KEEP finished previews and remove the rest. Files
/// another arrival is still writing are named working.* and are left alone,
/// unless a decode that was killed left one behind more than five minutes
/// ago. Nothing else in the directory is touched.
fn prune_previews(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let now = SystemTime::now();
    let mut finished = Vec::new();
    for entry in entries.flatten() {
        // Not followed: only regular files count, as `find -type f`.
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        let Ok(mtime) = meta.modified() else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        let name = entry.file_name();
        let name = name.as_bytes();
        if name.len() >= "preview..jpg".len()
            && name.starts_with(b"preview.")
            && name.ends_with(b".jpg")
        {
            finished.push((mtime, entry.path()));
        } else if name.starts_with(b"working.")
            && now
                .duration_since(mtime)
                .is_ok_and(|age| age > PREVIEW_STALE)
        {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    finished.sort_by_key(|(mtime, _)| std::cmp::Reverse(*mtime));
    for (_, path) in finished.into_iter().skip(PREVIEW_KEEP) {
        let _ = std::fs::remove_file(path);
    }
}

/// The arrival on the clipboard as well as announced: a link as its URL, an
/// image as the image, anything else as its path. A HEIC, HEIF or AVIF photo
/// goes on as a JPEG decoded from it, or as its path if that fails. wl-copy
/// forks a server to own the selection, so it gets its own unit too.
fn copy_to_clipboard(f: &Path) {
    let url = link_target(f);
    if !have("wl-copy") {
        return;
    }
    if let Some(u) = url {
        launch(
            &[OsStr::new("wl-copy")],
            Some(Stdin::Bytes(u.into_bytes())),
            None,
        );
        return;
    }
    let lower = f.as_os_str().to_string_lossy().to_lowercase();
    let decoded = if is_heif(&lower) {
        heif_to_jpeg(f)
    } else {
        None
    };
    let (image, mime) = match (&decoded, is_image(&lower)) {
        (Some((_, jpeg)), _) => (Some(jpeg.as_path()), "image/jpeg"),
        (None, Some(mime)) => (Some(f), mime),
        (None, None) => (None, ""),
    };
    match image {
        // wl-copy gets the JPEG as an open file descriptor, which outlives
        // the directory's removal below, so nothing has to wait for it.
        Some(path) => launch(
            &[
                OsStr::new("wl-copy"),
                OsStr::new("--type"),
                OsStr::new(mime),
            ],
            Some(Stdin::File(path)),
            None,
        ),
        None => launch(
            &[OsStr::new("wl-copy")],
            Some(Stdin::Bytes(f.as_os_str().as_bytes().to_vec())),
            None,
        ),
    }
    if let Some((dir, _)) = decoded {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// Save, copy, announce. Opening is left to a click on the notification, so
/// nothing runs on the person's behalf unasked. -t 8000 because the shell
/// treats the timeout as a floor of 5 s for low urgency, and this toast is
/// the only place the name of what landed appears.
pub fn cmd_handle(args: &[OsString]) -> i32 {
    let Some(f) = args.first().filter(|a| !a.is_empty()) else {
        die("usage: omdrop handle FILE");
    };
    let f = Path::new(f);
    copy_to_clipboard(f);
    let lower = f.as_os_str().to_string_lossy().to_lowercase();
    // Only images get a thumbnail, the way a screenshot notification does. A
    // HEIC, HEIF or AVIF gets a JPEG preview, since the notification daemon
    // cannot decode one.
    let image = if is_image(&lower).is_some() {
        Some(f.to_path_buf())
    } else if is_heif(&lower) {
        heic_preview(f)
    } else {
        None
    };
    let where_ = tildify(&dirname(f.as_os_str()).to_string_lossy());
    let what = if have("wl-copy") {
        format!("Copied to clipboard, saved to {where_}/")
    } else {
        format!("Saved to {where_}/")
    };
    // The sender chose the name, and omarchy-notification-send takes no `--`:
    // a name like `-t` or `--app-name=X` would be read as an option.
    let mut title = basename(f.as_os_str());
    if title.as_bytes().starts_with(b"-") {
        let mut dotted = OsString::from("./");
        dotted.push(&title);
        title = dotted;
    }
    let mut argv: Vec<OsString> = vec![
        "-t".into(),
        "8000".into(),
        title,
        format!("{what} (or click this)").into(),
    ];
    if let Some(image) = image {
        argv.push("--image".into());
        argv.push(image.into_os_string());
    }
    argv.extend([
        OsString::from("--exec"),
        ctx().command_path().as_os_str().to_owned(),
        "act".into(),
        "open".into(),
        f.as_os_str().to_owned(),
    ]);
    if crate::proc::run_no_stdout("omarchy-notification-send", &argv) != 0 {
        errln!("omdrop: notification failed for {}", f.display());
    }
    0
}

/// Follow the receiver's own log rather than the folder: it names the files
/// it stored, and an unrelated download landing there cannot fool it. Only
/// the receiver's own two records count, matched whole, and only names that
/// are regular files directly inside the download folder are acted on: a
/// sender's text can reach the log, and must never point this at anything else.
pub fn cmd_watch(args: &[String]) -> i32 {
    // --window SPAN is declaration only: `status` reads it off this unit's
    // arguments, and the deadline itself is a systemd timer.
    let once = args.iter().any(|a| a == "--once");
    let dir = effective_dir();
    outln!("omdrop watch: following {UNIT}, saving into {dir}");
    let Ok((read, write)) = crate::proc::pipe() else {
        return 1;
    };
    let mut cmd = Command::new("journalctl");
    cmd.args(["--user", "-u", UNIT, "-f", "-n", "0", "-o", "cat"])
        .stdout(Stdio::from(write))
        .stderr(Stdio::null());
    let journal = cmd.spawn();
    drop(cmd);
    let Ok(mut journal) = journal else {
        return 0;
    };
    let mut reader = crate::proc::LineReader::new(read);
    let mut handlers: Vec<Child> = Vec::new();
    // Transfers with an announced file, for --once.
    let mut announced: std::collections::HashSet<String> = std::collections::HashSet::new();
    loop {
        // Woken every second even without a record, so finished `handle`
        // children are reaped promptly rather than at the next arrival.
        let line = match reader.read_line(Some(
            std::time::Instant::now() + std::time::Duration::from_secs(1),
        )) {
            crate::proc::Read1::Line(l) => l,
            crate::proc::Read1::Timeout => {
                handlers.retain_mut(|c| matches!(c.try_wait(), Ok(None)));
                continue;
            }
            crate::proc::Read1::Eof | crate::proc::Read1::Signal => break,
        };
        handlers.retain_mut(|c| matches!(c.try_wait(), Ok(None)));
        let Some(names) = std::str::from_utf8(&line).ok().and_then(arrivals) else {
            continue;
        };
        let (found, missing) = resolve_arrivals(Path::new(&dir), &names);
        for name in missing {
            errln!("omdrop watch: receiver named '{name}', which is not a file in {dir}; ignored");
        }
        let self_exe = ctx().command_path().as_os_str();
        for path in &found {
            outln!("omdrop watch: announcing {}", path.display());
            // In its own transient unit, like `off` below: stopping this
            // service (`off`, or a one-file window closing right after this)
            // kills its whole cgroup, and a notification still decoding its
            // preview would be lost. systemd-run returns once the unit has
            // started. Without it, handle runs here, and a one-file window
            // waits for it before closing. MemoryMax caps what a decode of
            // a crafted photo can take: the unit is killed, not the session.
            let unit: [&OsStr; 8] = [
                "--user".as_ref(),
                "--quiet".as_ref(),
                "--collect".as_ref(),
                "-p".as_ref(),
                HANDLE_MEMORY_MAX.as_ref(),
                self_exe,
                "handle".as_ref(),
                path.as_os_str(),
            ];
            if run_quiet("systemd-run", &unit) == 0 {
                continue;
            }
            match Command::new(self_exe).arg("handle").arg(path).spawn() {
                Ok(c) => handlers.push(c),
                Err(e) => errln!("omdrop: {}: {e}", ctx().command_path().display()),
            }
        }
        // A one-file window closes once the first transfer is complete: a
        // link, or an upload's last record (`(N/N)`, or its only one), once
        // some record of that transfer has announced a file. An earlier
        // record of a long list does not close it.
        let complete = match &names {
            ArrivalNames::Link(_) => !found.is_empty(),
            ArrivalNames::Stored { tid, last, .. } => {
                if once && !found.is_empty() {
                    announced.insert(tid.clone());
                }
                *last && announced.contains(tid)
            }
        };
        if once && complete {
            for mut handler in handlers.drain(..) {
                let _ = handler.wait();
            }
            // In its OWN transient unit, not in this process: `off` stops
            // omdrop-watch.service -- this service -- and systemd kills the
            // whole cgroup, so an in-process `off` died partway and left the
            // receiver listening for a second file (twice, 2026-09-17).
            let args: [&OsStr; 6] = [
                "--user".as_ref(),
                "--quiet".as_ref(),
                "--collect".as_ref(),
                self_exe,
                "off".as_ref(),
                "--force".as_ref(),
            ];
            if run_quiet("systemd-run", &args) != 0 {
                run_quiet(self_exe, &["off", "--force"]);
            }
            let _ = journal.kill();
            let _ = journal.wait();
            return 0;
        }
    }
    let _ = journal.wait();
    0
}

/// What the receiver's `%(asctime)s %(levelname)s %(name)s: ` prefix
/// leaves: the message of an INFO record from the root logger.
fn receiver_info(line: &str) -> Option<&str> {
    let b = line.as_bytes();
    // 2026-10-10 16:14:20,098
    let stamp_ok = b.len() >= 23
        && b[..23].iter().enumerate().all(|(i, &c)| match i {
            4 | 7 => c == b'-',
            10 => c == b' ',
            13 | 16 => c == b':',
            19 => c == b',',
            _ => c.is_ascii_digit(),
        });
    if !stamp_ok {
        return None;
    }
    line[23..].strip_prefix(" INFO root: ")
}

/// What one of the receiver's records says it stored:
/// `upload TID: stored NAME` (the whole remainder is the one name, `, ` and
/// all, or empty when nothing was stored), `upload TID (K/N): stored NAME`
/// for file K of N, or `link stored as NAME.url -> http(s)://...`.
pub fn arrivals(line: &str) -> Option<ArrivalNames> {
    let msg = receiver_info(line)?;
    if let Some(rest) = msg.strip_prefix("upload ") {
        let (head, name) = rest.split_once(": stored ")?;
        let (tid, last) = match head.split_once(' ') {
            None => (head, true),
            Some((tid, part)) => {
                let (k, n) = part.strip_prefix('(')?.strip_suffix(')')?.split_once('/')?;
                let (k, n) = (record_number(k)?, record_number(n)?);
                if k > n {
                    return None;
                }
                (tid, k == n)
            }
        };
        let tid_ok = (1..=64).contains(&tid.len())
            && tid
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'));
        return tid_ok.then(|| ArrivalNames::Stored {
            tid: tid.to_string(),
            name: name.to_string(),
            last,
        });
    }
    let rest = msg.strip_prefix("link stored as ")?;
    let (name, url) = rest.split_once(" -> ")?;
    let name_ok = name.len() > 4 && name.ends_with(".url") && !name.contains([' ', '/']);
    let url_rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let url_ok = !url_rest.is_empty() && !url_rest.contains(char::is_whitespace);
    (name_ok && url_ok).then(|| ArrivalNames::Link(name.to_string()))
}

/// K or N of a `(K/N)` record number: 1 to 512 (an upload's member limit),
/// decimal digits only, no leading zero.
fn record_number(text: &str) -> Option<u16> {
    let ok = !text.is_empty()
        && text.len() <= 3
        && !text.starts_with('0')
        && text.bytes().all(|c| c.is_ascii_digit());
    ok.then(|| text.parse().ok())
        .flatten()
        .filter(|n| *n <= 512)
}

#[derive(Debug, PartialEq, Eq)]
pub enum ArrivalNames {
    /// An upload's record: its transfer, the one name (empty: none), and
    /// whether it is the transfer's last record.
    Stored {
        tid: String,
        name: String,
        last: bool,
    },
    Link(String),
}

/// A name is acted on only if it is a plain file name -- no slash, no
/// leading dot, no control characters -- naming a regular file directly in
/// the download folder, by lstat, so a symlink planted there is not followed.
fn arrived_file(dir: &Path, name: &str) -> Option<PathBuf> {
    if name.is_empty()
        || name.contains('/')
        || name.starts_with('.')
        || name.chars().any(char::is_control)
    {
        return None;
    }
    let path = dir.join(name);
    std::fs::symlink_metadata(&path)
        .ok()
        .filter(|m| m.file_type().is_file())
        .map(|_| path)
}

/// The file a record names, or the name that matched none. A record with no
/// name names nothing and is not a missing file.
pub fn resolve_arrivals(dir: &Path, names: &ArrivalNames) -> (Vec<PathBuf>, Vec<String>) {
    let name = match names {
        ArrivalNames::Link(name) => name,
        ArrivalNames::Stored { name, .. } if name.is_empty() => {
            return (Vec::new(), Vec::new());
        }
        ArrivalNames::Stored { name, .. } => name,
    };
    match arrived_file(dir, name) {
        Some(p) => (vec![p], Vec::new()),
        None => (Vec::new(), vec![name.clone()]),
    }
}

// ------------------------------------------------------------ link handler

/// freedesktop knows .url as application/x-mswinurl; .webloc is unknown to
/// shared-mime-info (it detects as text/xml and opens in an editor), so it
/// gets a type nothing installed claims.
const LINK_APP: &str = "netmojo.omdrop-links.desktop";
const LINK_MIME: &str = "netmojo.omdrop-webloc.xml";
const LINK_TYPES: [&str; 2] = ["application/x-mswinurl", "application/x-webloc"];

fn data_home() -> PathBuf {
    env_nonempty("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("{}/.local/share", home())))
}

fn mimeapps_list() -> PathBuf {
    ctx().config_home.join("mimeapps.list")
}

/// The default the user's own mimeapps.list names for a type, if any. Read
/// directly rather than through `xdg-mime query default`, which also answers
/// with any app that merely claims the type.
fn user_default(t: &str) -> String {
    let Ok(text) = std::fs::read(mimeapps_list()) else {
        return String::new();
    };
    let prefix = format!("{t}=");
    let mut in_defaults = false;
    for line in String::from_utf8_lossy(&text).split('\n') {
        if line.starts_with('[') {
            in_defaults = line == "[Default Applications]";
            continue;
        }
        if in_defaults && let Some(v) = line.strip_prefix(&prefix) {
            return v.split(';').next().unwrap_or("").to_string();
        }
    }
    String::new()
}

/// An Exec path, quoted as the Desktop Entry spec requires: backslash before
/// " ` $ and \ inside the quotes, every backslash doubled again because the
/// value is a key-file string, and % doubled so it is not a field code.
pub fn desktop_exec_quote(s: &str) -> String {
    let s = s
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('`', "\\`")
        .replace('$', "\\$");
    let s = s.replace('\\', "\\\\").replace('%', "%%");
    format!("\"{s}\"")
}

/// Write a file only when its content differs; true only if it wrote.
fn write_if_changed(path: &Path, content: &str) -> bool {
    if crate::util::read_trimmed(path).as_deref() == Some(content) {
        return false;
    }
    let written = path
        .parent()
        .map_or(Ok(()), std::fs::create_dir_all)
        .and_then(|()| std::fs::write(path, format!("{content}\n")));
    match written {
        Ok(()) => true,
        Err(e) => {
            errln!("omdrop: {}: {e}", path.display());
            false
        }
    }
}

/// Install the double-click handler; true only if it changed anything.
pub fn links_install(command: &Path) -> bool {
    let apps = data_home().join("applications");
    let mime = data_home().join("mime");
    let mut changed = false;
    let entry = format!(
        "[Desktop Entry]\nType=Application\nName=Omdrop link opener\nComment=Open a link an Apple device sent over AirDrop in the web browser\nExec={} open-link %f\nMimeType=application/x-mswinurl;application/x-webloc;\nNoDisplay=true\nTerminal=false",
        desktop_exec_quote(&command.to_string_lossy())
    );
    if write_if_changed(&apps.join(LINK_APP), &entry) {
        changed = true;
        run_quiet("update-desktop-database", &[apps.as_os_str()]);
    }
    let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<mime-info xmlns=\"http://www.freedesktop.org/standards/shared-mime-info\">\n  <mime-type type=\"application/x-webloc\">\n    <comment>Website location</comment>\n    <glob pattern=\"*.webloc\"/>\n  </mime-type>\n</mime-info>";
    if write_if_changed(&mime.join("packages").join(LINK_MIME), xml) {
        changed = true;
        if run_quiet("update-mime-database", &[mime.as_os_str()]) != 0 {
            errln!("omdrop: update-mime-database failed, so .webloc files may still open as XML.");
        }
    }
    for t in LINK_TYPES {
        let current = user_default(t);
        if current.is_empty() {
            // xdg-mime cannot create the folder, and exits 0 when it fails,
            // so make the folder first and check the result afterwards.
            if let Some(dir) = mimeapps_list().parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            run_quiet("xdg-mime", &["default", LINK_APP, t]);
            if user_default(t) == LINK_APP {
                changed = true;
            } else {
                errln!(
                    "omdrop: could not make Omdrop open {t} files. Run: xdg-mime default {LINK_APP} {t}"
                );
            }
        } else if current != LINK_APP {
            errln!(
                "Left {t} opening with {current}, which you chose. To open received links with Omdrop: xdg-mime default {LINK_APP} {t}"
            );
        }
    }
    if changed {
        outln!("Set up double-clicking a received .url or .webloc link to open it in the browser.");
    }
    changed
}

/// Reverse links_install. A default is removed only while it still names
/// us, so a user who pointed a type elsewhere keeps their choice.
fn links_remove() -> i32 {
    let apps = data_home().join("applications");
    let mime = data_home().join("mime");
    let list = mimeapps_list();
    for t in LINK_TYPES {
        if user_default(t) != LINK_APP || !crate::util::is_writable(&list) {
            continue;
        }
        let Ok(text) = std::fs::read(&list) else {
            continue;
        };
        let text = String::from_utf8_lossy(&text);
        let (plain, semi) = (format!("{t}={LINK_APP}"), format!("{t}={LINK_APP};"));
        let mut in_defaults = false;
        let mut out = String::new();
        for line in text.lines() {
            if line.starts_with('[') {
                in_defaults = line == "[Default Applications]";
            }
            if in_defaults && (line == plain || line == semi) {
                continue;
            }
            out.push_str(line);
            out.push('\n');
        }
        if let Err(e) =
            crate::util::atomic_write(&list, "mimeapps.list.omdrop.", out.as_bytes(), 0o644)
        {
            errln!("omdrop: could not rewrite {}: {e}", list.display());
        }
    }
    if lexists(&apps.join(LINK_APP)) {
        let _ = std::fs::remove_file(apps.join(LINK_APP));
        run_quiet("update-desktop-database", &[apps.as_os_str()]);
    }
    let pkg = mime.join("packages").join(LINK_MIME);
    if lexists(&pkg) {
        let _ = std::fs::remove_file(&pkg);
        run_quiet("update-mime-database", &[mime.as_os_str()]);
    }
    outln!("Removed the handler for received .url and .webloc links.");
    0
}

pub fn cmd_links(args: &[String]) -> i32 {
    match args.first().map(String::as_str).unwrap_or("") {
        "install" => {
            if !links_install(ctx().command_path()) {
                outln!("The link handler was already set up.");
            }
            0
        }
        "remove" => links_remove(),
        _ => die("usage: omdrop links install|remove"),
    }
}

// ------------------------------------------------------------------- skill

/// The skill directories Omarchy provisions for the agents it launches. Only
/// existing ones: a missing one belongs to an agent that is not installed.
fn skill_dirs() -> Vec<PathBuf> {
    let h = home();
    [
        ".agents/skills",
        ".claude/skills",
        ".codex/skills",
        ".pi/agent/skills",
    ]
    .iter()
    .map(|d| PathBuf::from(format!("{h}/{d}")))
    .collect()
}

/// A one-line pointer from `omdrop setup`, when an agent is set up and the
/// skill is not linked for it. Only `omdrop skill install` writes the links:
/// never setup, never `on`, so a removed skill stays removed. It changes
/// nothing.
pub fn skills_offer() {
    if skills_offer_needed(&skill_dirs()) {
        outln!("To let AI agents use omdrop, run: omdrop skill install");
    }
}

/// An agent's skill directory exists and has no `omdrop` entry at all.
fn skills_offer_needed(dirs: &[PathBuf]) -> bool {
    dirs.iter()
        .any(|d| d.is_dir() && std::fs::symlink_metadata(d.join("omdrop")).is_err())
}

/// An entry named omdrop is replaced only when absent, a dangling link, or a
/// link into some plugin's skills/omdrop -- judged by the link's own target,
/// not its resolution, because a plugin directory can itself be a link into
/// a source checkout. 0 linked something, 1 all current or left in place,
/// 2 a link could not be made.
pub fn skills_install(plugin: &Path, quiet: bool) -> i32 {
    skills_install_into(plugin, &skill_dirs(), quiet)
}

fn skills_install_into(plugin: &Path, dirs: &[PathBuf], quiet: bool) -> i32 {
    let skill = plugin.join("skills/omdrop");
    if !crate::util::is_readable(&skill.join("SKILL.md")) {
        if !quiet {
            errln!("omdrop could not find its skill at {}.", skill.display());
        }
        return 2;
    }
    let skill_s = skill.to_string_lossy().into_owned();
    let (mut changed, mut failed) = (false, false);
    for dir in dirs {
        if !dir.is_dir() {
            continue;
        }
        let link = dir.join("omdrop");
        if is_symlink(&link) {
            let raw = std::fs::read_link(&link)
                .map(|r| r.to_string_lossy().into_owned())
                .unwrap_or_default();
            if raw == skill_s {
                continue;
            }
            if link.exists() && !glob_match("*/plugins/*/skills/omdrop", &raw) {
                if !quiet {
                    errln!("Left {} alone: it points at {raw}.", link.display());
                }
                continue;
            }
        } else if link.exists() {
            if !quiet {
                errln!(
                    "Left {} alone: it is not a link omdrop made.",
                    link.display()
                );
            }
            continue;
        }
        let made = (|| {
            if lexists(&link) {
                std::fs::remove_file(&link)?;
            }
            std::os::unix::fs::symlink(&skill, &link)
        })();
        match made {
            Ok(()) => changed = true,
            Err(_) => {
                if !quiet {
                    errln!("omdrop could not link its skill at {}.", link.display());
                }
                failed = true;
            }
        }
    }
    if changed && !quiet {
        outln!("Installed the omdrop skill for AI agents.");
    }
    if failed {
        2
    } else if changed {
        0
    } else {
        1
    }
}

/// Removes only links into some plugin's skills/omdrop or this one's, live
/// or dangling. Fails if any of those could not be removed.
fn skills_remove() -> i32 {
    let mine = ctx()
        .plugin_dir()
        .map(|p| p.join("skills/omdrop").to_string_lossy().into_owned());
    let mut failed = false;
    for dir in skill_dirs() {
        let link = dir.join("omdrop");
        if !is_symlink(&link) {
            continue;
        }
        let raw = std::fs::read_link(&link)
            .map(|r| r.to_string_lossy().into_owned())
            .unwrap_or_default();
        if !(glob_match("*/plugins/*/skills/omdrop", &raw) || mine.as_deref() == Some(raw.as_str()))
        {
            continue;
        }
        if std::fs::remove_file(&link).is_err() {
            errln!("omdrop could not remove {}.", link.display());
            failed = true;
        }
    }
    if failed {
        return 1;
    }
    outln!("Removed the omdrop skill for AI agents.");
    0
}

pub fn cmd_skill(args: &[String]) -> i32 {
    match args.first().map(String::as_str).unwrap_or("") {
        "install" => {
            let plugin = ctx()
                .plugin_dir()
                .unwrap_or_else(|| die("omdrop cannot tell where it is installed."));
            let rc = skills_install(plugin, false);
            if rc == 1 {
                outln!("The omdrop skill for AI agents was already installed.");
            }
            if rc == 2 { 1 } else { 0 }
        }
        "remove" => skills_remove(),
        _ => die("usage: omdrop skill install|remove"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_url_line_outside_the_shortcut_section_is_not_the_link() {
        assert_eq!(
            url_file_target(b"[InternetShortcut]\r\nURL=https://example.com/a?b=1\r\n"),
            "https://example.com/a?b=1"
        );
        assert_eq!(
            url_file_target(b"[Other]\nURL=https://decoy.example/\n[InternetShortcut]\nURL=https://example.com/\n"),
            "https://example.com/"
        );
        assert_eq!(
            url_file_target(b"[ Internet Shortcut ]\n  url \t= \thttps://x.example/ \t\n"),
            "https://x.example/"
        );
        assert_eq!(
            url_file_target(b"[OtherSection]\nURL=https://example.com/\n"),
            ""
        );
    }

    #[test]
    fn only_web_pages_are_web_links() {
        for ok in [
            "https://example.com/",
            "HTTP://e.x",
            "https://example.com/?a=1&b=2",
        ] {
            assert!(web_url(ok), "{ok}");
        }
        for bad in [
            "file:///etc/passwd",
            "smb://server/share",
            "x-app://run",
            "javascript:alert(1)",
            "https:///no-host",
            "https://example.com/a b",
            "https://",
            "https://e.x/\u{7}",
        ] {
            assert!(!web_url(bad), "{bad}");
        }
    }

    #[test]
    fn weblocs_are_read_whether_xml_or_binary() {
        let mut dict = plist::Dictionary::new();
        dict.insert(
            "URL".into(),
            plist::Value::String(" https://example.com/?a=1&b=2 ".into()),
        );
        let value = plist::Value::Dictionary(dict);
        let mut xml = Vec::new();
        value.to_writer_xml(&mut xml).unwrap();
        let mut bin = Vec::new();
        value.to_writer_binary(&mut bin).unwrap();
        assert_eq!(
            webloc_target(&xml).as_deref(),
            Some("https://example.com/?a=1&b=2")
        );
        assert_eq!(
            webloc_target(&bin).as_deref(),
            Some("https://example.com/?a=1&b=2")
        );
        assert_eq!(webloc_target(b"not a property list"), None);
    }

    /// `root` plus a binary plist's one data object referenced 1 000 times:
    /// the plist writer stores equal data once. 30 KB on disk, 30 MB decoded.
    fn shared_reference_bomb(mut root: plist::Dictionary) -> Vec<u8> {
        let pad = plist::Value::Data(vec![0x41; 30_000]);
        root.insert("Pad".into(), plist::Value::Array(vec![pad; 1_000]));
        let mut out = Vec::new();
        plist::Value::Dictionary(root)
            .to_writer_binary(&mut out)
            .unwrap();
        out
    }

    #[test]
    fn a_webloc_that_expands_past_its_size_is_not_a_link() {
        let mut dict = plist::Dictionary::new();
        dict.insert("URL".into(), "https://example.com/".into());
        let bomb = shared_reference_bomb(dict);
        assert!(bomb.len() as u64 <= LINK_MAX);
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.webloc");
        std::fs::write(&f, &bomb).unwrap();
        assert_eq!(link_url(&f), None);
    }

    const TS: &str = "2026-10-10 16:14:20,098";

    fn stored(tid: &str, name: &str, last: bool) -> ArrivalNames {
        ArrivalNames::Stored {
            tid: tid.into(),
            name: name.into(),
            last,
        }
    }

    #[test]
    fn only_the_receivers_own_records_name_arrivals() {
        let stored_line = format!("{TS} INFO root: upload 1A2B-3c_d.e: stored a.jpg, b c.png");
        assert_eq!(
            arrivals(&stored_line),
            Some(stored("1A2B-3c_d.e", "a.jpg, b c.png", true))
        );
        // Nothing stored: a record naming no file.
        assert_eq!(
            arrivals(&format!("{TS} INFO root: upload X: stored ")),
            Some(stored("X", "", true))
        );
        // File K of N, one record each: only the last completes.
        for (part, last) in [
            ("1/3", false),
            ("2/3", false),
            ("3/3", true),
            ("512/512", true),
        ] {
            let line = format!("{TS} INFO root: upload T-1 ({part}): stored a.jpg, b (1/2): c");
            assert_eq!(
                arrivals(&line),
                Some(stored("T-1", "a.jpg, b (1/2): c", last)),
                "{line}"
            );
        }
        let link = format!("{TS} INFO root: link stored as Example.url -> https://example.com/");
        assert_eq!(
            arrivals(&link),
            Some(ArrivalNames::Link("Example.url".into()))
        );
        for forged in [
            "upload ABC: stored /home/u/secret.png".to_string(),
            format!("{TS} INFO root: GET /Discover from Mac upload X: stored /etc/passwd"),
            format!("{TS} DEBUG root: upload X: stored a.jpg"),
            format!("x{TS} INFO root: upload X: stored a.jpg"),
            format!("{TS} INFO root: upload X Y: stored a.jpg"),
            format!("{TS} INFO root: upload {}: stored a.jpg", "x".repeat(65)),
            format!("{TS} INFO root: GET / from M upload X (1/1): stored /etc/passwd"),
            format!("{TS} INFO root: upload X (0/1): stored a.jpg"),
            format!("{TS} INFO root: upload X (2/1): stored a.jpg"),
            format!("{TS} INFO root: upload X (1/513): stored a.jpg"),
            format!("{TS} INFO root: upload X (01/2): stored a.jpg"),
            format!("{TS} INFO root: upload X ( 1/2): stored a.jpg"),
            format!("{TS} INFO root: upload X (1/2) : stored a.jpg"),
            format!("{TS} INFO root: upload X  (1/2): stored a.jpg"),
            format!("{TS} INFO root: upload X (+1/2): stored a.jpg"),
            format!("{TS} INFO root: upload X (1/2: stored a.jpg"),
            format!("{TS} INFO root: link stored as ../a.url -> https://e.x/"),
            format!("{TS} INFO root: link stored as a.url -> file:///etc/passwd"),
            format!("{TS} INFO root: link stored as a.webloc -> https://e.x/"),
        ] {
            assert_eq!(arrivals(&forged), None, "{forged}");
        }
    }

    #[test]
    fn only_regular_files_directly_in_the_download_folder_are_acted_on() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("Downloads");
        std::fs::create_dir(&dir).unwrap();
        let outside = tmp.path().join("secret.png");
        std::fs::write(&outside, "x").unwrap();
        for name in ["a.jpg", "two, parts.txt", "b.png", ".hidden"] {
            std::fs::write(dir.join(name), "x").unwrap();
        }
        std::os::unix::fs::symlink(&outside, dir.join("link.png")).unwrap();
        std::fs::create_dir(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub/c.png"), "x").unwrap();

        for name in ["a.jpg", "two, parts.txt", "b.png"] {
            let (found, missing) = resolve_arrivals(&dir, &stored("T", name, true));
            assert_eq!(found, [dir.join(name)]);
            assert!(missing.is_empty(), "{missing:?}");
        }
        // The remainder is one name, never split on ", ": a file named like
        // its first piece is not what arrived (hume, on plugin #106).
        std::fs::write(dir.join("private.png, sent.txt"), "x").unwrap();
        std::fs::write(dir.join("private.png"), "x").unwrap();
        let (found, missing) = resolve_arrivals(&dir, &stored("T", "private.png, sent.txt", true));
        assert_eq!(found, [dir.join("private.png, sent.txt")]);
        assert!(missing.is_empty());
        let (found, missing) = resolve_arrivals(&dir, &stored("T", "a.jpg, b.png", true));
        assert!(found.is_empty(), "{found:?}");
        assert_eq!(missing, ["a.jpg, b.png"]);
        // No name: nothing found, nothing missing.
        assert_eq!(
            resolve_arrivals(&dir, &stored("T", "", true)),
            (Vec::new(), Vec::new())
        );

        let outside = outside.display().to_string();
        for name in [
            outside.as_str(),
            "link.png",
            ".hidden",
            "sub/c.png",
            "sub",
            "gone.jpg",
        ] {
            let (found, missing) = resolve_arrivals(&dir, &stored("T", name, true));
            assert!(found.is_empty(), "{found:?}");
            assert_eq!(missing, [name]);
        }

        let (found, _) = resolve_arrivals(&dir, &ArrivalNames::Link("link.png".into()));
        assert!(found.is_empty());
    }

    #[test]
    fn desktop_exec_paths_are_quoted_twice() {
        assert_eq!(desktop_exec_quote("/a b/omdrop"), "\"/a b/omdrop\"");
        assert_eq!(desktop_exec_quote("/x$y%z\\w"), "\"/x\\\\$y%%z\\\\\\\\w\"");
    }

    #[test]
    fn a_skill_link_that_cannot_be_made_fails_the_install() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let plugin = tmp.path().join("plugin");
        std::fs::create_dir_all(plugin.join("skills/omdrop")).unwrap();
        std::fs::write(plugin.join("skills/omdrop/SKILL.md"), "x").unwrap();
        let skills = tmp.path().join("home/.claude/skills");
        std::fs::create_dir_all(&skills).unwrap();
        let dirs = [tmp.path().join("home/.codex/skills"), skills.clone()];
        std::fs::set_permissions(&skills, std::fs::Permissions::from_mode(0o500)).unwrap();
        let writable = std::fs::write(skills.join("probe"), "").is_ok();
        let rc = skills_install_into(&plugin, &dirs, true);
        std::fs::set_permissions(&skills, std::fs::Permissions::from_mode(0o700)).unwrap();
        if writable {
            return; // running as a user who can write anywhere
        }
        assert_eq!(rc, 2);
        assert!(!lexists(&skills.join("omdrop")));
        std::os::unix::fs::symlink(
            tmp.path().join("plugins/gone/skills/omdrop"),
            skills.join("omdrop"),
        )
        .unwrap();
        assert_eq!(skills_install_into(&plugin, &dirs, true), 0);
        assert_eq!(
            std::fs::read_link(skills.join("omdrop")).unwrap(),
            plugin.join("skills/omdrop")
        );
    }

    #[test]
    fn setup_offers_the_skill_only_where_an_agent_has_no_omdrop_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let claude = tmp.path().join(".claude/skills");
        let codex = tmp.path().join(".codex/skills");
        // No agent installed: nothing to offer.
        assert!(!skills_offer_needed(&[claude.clone(), codex.clone()]));
        std::fs::create_dir_all(&claude).unwrap();
        assert!(skills_offer_needed(&[claude.clone(), codex.clone()]));
        // A removed skill stays removed: any entry, even a dangling link, means
        // the user has decided, so there is nothing to offer.
        std::os::unix::fs::symlink(tmp.path().join("gone"), claude.join("omdrop")).unwrap();
        assert!(!skills_offer_needed(&[claude, codex]));
    }
}
