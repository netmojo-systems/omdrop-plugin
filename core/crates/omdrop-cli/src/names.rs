//! Names nearby devices gave a named lookup, shared by every program that runs
//! `omdrop peers`, and the lock that lets one named lookup run at a time.
//!
//! Each name a lookup learns goes in `peer-names.json` in the runtime
//! directory, dated, so every client shows it while its device stays in the
//! table. A `peers -n` that finds another lookup holding `peer-lookup.lock`
//! follows that lookup instead of advertising and connecting beside it.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::ctx::ctx;
use crate::send::{Row, is_mac, parse_row, placeholder};
use crate::util::{atomic_write, is_space, mkdir_private};

/// How long a learned name is shown: AWDL addresses rotate, so an old one is
/// more likely nobody's.
pub const NAME_TTL: Duration = Duration::from_secs(30 * 60);

/// The most names kept, the newest: a device answering from a new address
/// each lookup cannot grow the file past this.
const NAMES_MAX: usize = 256;

/// The longest name kept, in UTF-8 bytes: the core sender's own cap
/// (`PEER_NAME_MAX_BYTES` in omdrop-send).
const NAME_MAX_BYTES: usize = 255;

/// The most of the file read: `NAMES_MAX` names at their longest, every byte
/// escaped, fit.
const FILE_MAX_BYTES: u64 = 1 << 20;

/// How long a store waits for another, which takes milliseconds, before it
/// keeps nothing.
const STORE_LOCK_WAIT: Duration = Duration::from_secs(2);

/// Tries for the lock while only watchers hold it, each for an instant,
/// before taking them for a lookup.
const TAKE_TRIES: usize = 100;

const NAMES_FILE: &str = "peer-names.json";
const NAMES_LOCK: &str = "peer-names.lock";
const LOOKUP_LOCK: &str = "peer-lookup.lock";

/// Names by address, each with when it was learned.
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Names(BTreeMap<String, Learned>);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Learned {
    name: String,
    /// Seconds since the epoch.
    at: u64,
}

impl Names {
    /// The names in `bytes` still fresh at `now`. Anything `store` would not
    /// have written is dropped: a corrupted file is no names, and the next
    /// store replaces it.
    fn parse(bytes: &[u8], now: u64) -> Self {
        let Ok(Self(mut names)) = serde_json::from_slice(bytes) else {
            return Self::default();
        };
        names.retain(|mac, l| is_mac(mac) && keepable(&l.name) && fresh(l.at, now));
        Self(names)
    }

    /// Remember the name `row` carries; false when it carries none.
    pub fn learn(&mut self, row: &Row, now: u64) -> bool {
        let name = row.name.trim();
        if !keepable(name) {
            return false;
        }
        self.0.insert(
            row.mac.clone(),
            Learned {
                name: name.to_string(),
                at: now,
            },
        );
        true
    }

    pub fn get(&self, mac: &str) -> Option<&str> {
        self.0.get(mac).map(|l| l.name.as_str())
    }

    /// The addresses and names learned at `at` or later.
    pub fn since(&self, at: u64) -> impl Iterator<Item = (&str, &str)> {
        self.0
            .iter()
            .filter(move |(_, l)| l.at >= at)
            .map(|(mac, l)| (mac.as_str(), l.name.as_str()))
    }

    /// Give `row` the name learned for its address when it has none of its
    /// own and the radio hears it now; true when it did.
    pub fn fill(&self, row: &mut Row) -> bool {
        if !placeholder(row.name.trim()) || !heard_now(row) {
            return false;
        }
        let Some(name) = self.get(&row.mac) else {
            return false;
        };
        row.name = name.to_string();
        true
    }

    /// `listing` with each row that has no name given its learned one, in
    /// the name column `--names` prints; every other line as it was.
    pub fn fill_listing(&self, listing: &str) -> String {
        let lines: Vec<String> = listing
            .split('\n')
            .map(|line| {
                let Some(mut row) = parse_row(line) else {
                    return line.to_string();
                };
                let own = row.name.len();
                if !self.fill(&mut row) {
                    return line.to_string();
                }
                // The row's own name is the end of the line.
                let head = line[..line.len() - own].trim_end_matches(is_space);
                format!("{head}  {}", row.name)
            })
            .collect();
        lines.join("\n")
    }

    /// Keep only the newest `NAMES_MAX`.
    fn trim(&mut self) {
        if self.0.len() <= NAMES_MAX {
            return;
        }
        let mut newest: Vec<(u64, String)> =
            self.0.iter().map(|(mac, l)| (l.at, mac.clone())).collect();
        newest.sort_unstable_by(|a, b| b.cmp(a));
        for (_, mac) in newest.drain(NAMES_MAX..) {
            self.0.remove(&mac);
        }
    }
}

/// The radio has a signal reading for `row`: a pinned address with none can
/// be one the device has already left behind.
pub fn heard_now(row: &Row) -> bool {
    row.rssi != "?"
}

/// A name worth keeping: not one of the sender's placeholders, one line, and
/// no longer than a cleaned name can be.
fn keepable(name: &str) -> bool {
    !placeholder(name) && name.len() <= NAME_MAX_BYTES && !name.contains(['\n', '\r'])
}

/// Learned within `NAME_TTL` of `now`. A time ahead of the clock is not.
fn fresh(at: u64, now: u64) -> bool {
    now.checked_sub(at)
        .is_some_and(|age| age < NAME_TTL.as_secs())
}

/// Seconds since the epoch, as names are dated.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The names learned within `NAME_TTL`. A missing or unreadable file is none.
pub fn load() -> Names {
    load_in(&ctx().state_dir(), now())
}

fn load_in(dir: &Path, now: u64) -> Names {
    read_capped(&dir.join(NAMES_FILE)).map_or_else(Names::default, |b| Names::parse(&b, now))
}

/// A regular file's bytes, or `None` past `FILE_MAX_BYTES`. Never a link,
/// and never a wait on something that is not a file.
fn read_capped(path: &Path) -> Option<Vec<u8>> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(FILE_MAX_BYTES + 1).read_to_end(&mut bytes).ok()?;
    u64::try_from(bytes.len())
        .is_ok_and(|n| n <= FILE_MAX_BYTES)
        .then_some(bytes)
}

/// Keep the names `rows` carry. Read, merged and replaced whole under
/// `peer-names.lock`, so lookups that end together all keep theirs. Best
/// effort: a file that cannot be written costs only the sharing.
pub fn store(rows: &[Row]) {
    store_in(&ctx().state_dir(), rows, now());
}

fn store_in(dir: &Path, rows: &[Row], now: u64) {
    if !rows.iter().any(|r| keepable(r.name.trim())) || mkdir_private(dir).is_err() {
        return;
    }
    let Some(lock) = open_lock(&dir.join(NAMES_LOCK)) else {
        return;
    };
    let deadline = Instant::now() + STORE_LOCK_WAIT;
    loop {
        match try_flock(&lock, libc::LOCK_EX) {
            Ok(true) => break,
            Ok(false) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            _ => return,
        }
    }
    let mut names = load_in(dir, now);
    for row in rows {
        names.learn(row, now);
    }
    names.trim();
    if let Ok(json) = serde_json::to_vec(&names) {
        let _ = atomic_write(&dir.join(NAMES_FILE), ".peer-names.", &json, 0o600);
    }
}

/// Whose named lookup runs now.
pub enum Lookup {
    /// This process's.
    Ours(Turn),
    /// Another process's.
    Running(Watch),
}

/// The named lookup this process runs: `peer-lookup.lock` is held until this
/// is dropped, and holds when it was taken. `None`: the lock could not be
/// used, so nothing coordinates it.
pub struct Turn {
    _lock: Option<File>,
}

/// Another process's named lookup, watched through the lock it holds.
pub struct Watch {
    lock: File,
}

impl Watch {
    /// Whether that lookup still runs. Looked at by taking the lock shared,
    /// for an instant, which `lookup` tells apart from a lookup.
    pub fn running(&self) -> bool {
        match try_flock(&self.lock, libc::LOCK_SH) {
            Ok(true) => {
                unlock(&self.lock);
                false
            }
            Ok(false) => true,
            Err(_) => false,
        }
    }

    /// When that lookup took the lock, in seconds since the epoch as names are
    /// dated; `None` until it has written it there, an instant after taking it.
    pub fn began(&self) -> Option<u64> {
        let mut buf = [0u8; 24];
        let n = self.lock.read_at(&mut buf, 0).ok()?;
        std::str::from_utf8(buf.get(..n)?).ok()?.trim().parse().ok()
    }
}

/// Take `peer-lookup.lock` for a named lookup, unless another lookup holds it.
/// Close-on-exec, so the sender and its advert cannot hold it after us.
pub fn lookup() -> Lookup {
    let dir = ctx().state_dir();
    if mkdir_private(&dir).is_err() {
        return Lookup::Ours(Turn { _lock: None });
    }
    lookup_at(&dir.join(LOOKUP_LOCK))
}

fn lookup_at(path: &Path) -> Lookup {
    let Some(file) = open_lock(path) else {
        return Lookup::Ours(Turn { _lock: None });
    };
    for _ in 0..TAKE_TRIES {
        match try_flock(&file, libc::LOCK_EX) {
            Ok(true) => {
                mark_began(&file);
                return Lookup::Ours(Turn { _lock: Some(file) });
            }
            Ok(false) => {}
            Err(_) => return Lookup::Ours(Turn { _lock: None }),
        }
        // Held exclusive by a lookup, or shared for an instant by a watcher,
        // which is no lookup.
        match try_flock(&file, libc::LOCK_SH) {
            Ok(true) => unlock(&file),
            Ok(false) => return Lookup::Running(Watch { lock: file }),
            Err(_) => return Lookup::Ours(Turn { _lock: None }),
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    Lookup::Running(Watch { lock: file })
}

/// Write when this lookup took the lock, for `Watch::began`. Best effort: a
/// follower that cannot read it counts from its own start.
fn mark_began(file: &File) {
    let text = format!("{}\n", now());
    if file.write_all_at(text.as_bytes(), 0).is_ok() {
        let _ = file.set_len(text.len() as u64);
    }
}

fn open_lock(path: &Path) -> Option<File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .ok()
}

/// flock(2) without waiting: true when taken, false when another holds it.
fn try_flock(file: &File, op: libc::c_int) -> io::Result<bool> {
    loop {
        // SAFETY: flock on a descriptor `file` owns; released when it closes.
        if unsafe { libc::flock(file.as_raw_fd(), op | libc::LOCK_NB) } == 0 {
            return Ok(true);
        }
        let e = io::Error::last_os_error();
        match e.kind() {
            io::ErrorKind::WouldBlock => return Ok(false),
            io::ErrorKind::Interrupted => {}
            _ => return Err(e),
        }
    }
}

fn unlock(file: &File) {
    // SAFETY: flock on a descriptor `file` owns.
    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    const A: &str = "e2:9d:03:6c:58:23";
    const B: &str = "22:8b:38:31:89:4e";
    const C: &str = "f2:f2:ee:c4:5a:f7";
    const T: u64 = 1_762_900_000;

    fn row(mac: &str, name: &str) -> Row {
        Row {
            mac: mac.to_string(),
            rssi: "-40".to_string(),
            name: name.to_string(),
        }
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn a_stored_name_is_kept_until_it_expires() {
        let dir = tempfile::tempdir().unwrap();
        let run = dir.path().join("omdrop");
        store_in(&run, &[row(A, "Studio Mac ")], T);
        let ttl = NAME_TTL.as_secs();
        assert_eq!(load_in(&run, T).get(A), Some("Studio Mac"));
        assert_eq!(load_in(&run, T + ttl - 1).get(A), Some("Studio Mac"));
        assert_eq!(load_in(&run, T + ttl), Names::default());
        assert_eq!(load_in(&run, T - 1), Names::default(), "dated ahead");
        assert_eq!(mode(&run), 0o700);
        assert_eq!(mode(&run.join(NAMES_FILE)), 0o600);
    }

    #[test]
    fn a_store_keeps_what_earlier_stores_learned_and_relearning_refreshes() {
        let dir = tempfile::tempdir().unwrap();
        store_in(dir.path(), &[row(A, "Studio Mac")], T);
        store_in(dir.path(), &[row(B, "hume")], T + 1);
        let names = load_in(dir.path(), T + 1);
        assert_eq!(
            (names.get(A), names.get(B)),
            (Some("Studio Mac"), Some("hume"))
        );
        let ttl = NAME_TTL.as_secs();
        store_in(dir.path(), &[row(A, "Studio Mac")], T + ttl - 1);
        let names = load_in(dir.path(), T + 1 + ttl);
        assert_eq!((names.get(A), names.get(B)), (Some("Studio Mac"), None));
    }

    #[test]
    fn placeholders_are_never_kept() {
        let rows = [row(A, ""), row(B, "(no response)"), row(C, " (anonymous) ")];
        let mut names = Names::default();
        for r in &rows {
            assert!(!names.learn(r, T), "{r:?}");
        }
        assert_eq!(names, Names::default());
        let dir = tempfile::tempdir().unwrap();
        store_in(dir.path(), &rows, T);
        assert!(!dir.path().join(NAMES_FILE).exists());
        assert!(!names.learn(&row(A, &"x".repeat(NAME_MAX_BYTES + 1)), T));
    }

    #[test]
    fn names_fill_only_rows_of_the_listing_that_have_none() {
        let mut names = Names::default();
        for (mac, name) in [(A, "Studio Mac"), (B, "hume"), (C, "Old Name")] {
            names.learn(&row(mac, name), T);
        }
        names.learn(&row("02:00:00:00:00:01", "gone"), T);
        let listing = "e2:9d:03:6c:58:23   -47 dBm  [fe80::1%awdl0]:8770\n\
             22:8b:38:31:89:4e   -34 dBm  [fe80::2%awdl0]:8770  (no response)\n\
             f2:f2:ee:c4:5a:f7     ? dBm  [fe80::3%awdl0]:8770  Own Name\n\
             b2:c4:98:5e:e6:be     ? dBm  [fe80::4%awdl0]:8770  (anonymous)\n\
             noise";
        assert_eq!(
            names.fill_listing(listing),
            "e2:9d:03:6c:58:23   -47 dBm  [fe80::1%awdl0]:8770  Studio Mac\n\
             22:8b:38:31:89:4e   -34 dBm  [fe80::2%awdl0]:8770  hume\n\
             f2:f2:ee:c4:5a:f7     ? dBm  [fe80::3%awdl0]:8770  Own Name\n\
             b2:c4:98:5e:e6:be     ? dBm  [fe80::4%awdl0]:8770  (anonymous)\n\
             noise"
        );
        assert_eq!(names.fill_listing(""), "");
    }

    #[test]
    fn an_address_the_radio_no_longer_hears_keeps_no_learned_name() {
        // A Mac rotates its AWDL address; the old one stays pinned without a
        // signal and must not be listed as a second "Office Mac".
        let mut names = Names::default();
        for (mac, name) in [(A, "Office Mac"), (B, "Office Mac")] {
            names.learn(&row(mac, name), T);
        }
        let listing = "e2:9d:03:6c:58:23     ? dBm  [fe80::1%awdl0]:8770  (no response)\n\
             22:8b:38:31:89:4e   -45 dBm  [fe80::2%awdl0]:8770  (no response)";
        assert_eq!(
            names.fill_listing(listing),
            "e2:9d:03:6c:58:23     ? dBm  [fe80::1%awdl0]:8770  (no response)\n\
             22:8b:38:31:89:4e   -45 dBm  [fe80::2%awdl0]:8770  Office Mac"
        );
    }

    #[test]
    fn a_corrupted_file_is_no_names_until_the_next_store_replaces_it() {
        for bytes in [
            &b"not json"[..],
            b"",
            b"[]",
            b"{\"e2:9d:03:6c:58:23\": {\"name\": 7, \"at\": 1}}",
            &[0xff, 0xfe, 0x00],
        ] {
            assert_eq!(Names::parse(bytes, T), Names::default(), "{bytes:?}");
        }
        // Only entries a store could have written survive.
        let mixed = format!(
            r#"{{"{A}": {{"name": "Studio Mac", "at": {T}}},
                "E2:9D:03:6C:58:24": {{"name": "upper", "at": {T}}},
                "{B}": {{"name": "(no response)", "at": {T}}},
                "{C}": {{"name": "two\nlines", "at": {T}}}}}"#
        );
        let names = Names::parse(mixed.as_bytes(), T);
        assert_eq!(names.since(0).collect::<Vec<_>>(), vec![(A, "Studio Mac")]);

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(NAMES_FILE), "{\"e2:9d").unwrap();
        assert_eq!(load_in(dir.path(), T), Names::default());
        store_in(dir.path(), &[row(B, "hume")], T);
        assert_eq!(
            load_in(dir.path(), T).since(0).collect::<Vec<_>>(),
            vec![(B, "hume")]
        );
    }

    #[test]
    fn only_the_newest_names_are_kept() {
        let dir = tempfile::tempdir().unwrap();
        let rows: Vec<Row> = (0..NAMES_MAX + 10)
            .map(|i| row(&format!("02:00:00:00:{:02x}:{:02x}", i / 256, i % 256), "x"))
            .collect();
        for (i, r) in (0u64..).zip(&rows) {
            store_in(dir.path(), std::slice::from_ref(r), T + i);
        }
        let names = load_in(dir.path(), T + 400);
        assert_eq!(names.since(0).count(), NAMES_MAX);
        assert_eq!(names.get(&rows[9].mac), None);
        assert_eq!(names.get(&rows[10].mac), Some("x"));
    }

    #[test]
    fn one_named_lookup_runs_at_a_time() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(LOOKUP_LOCK);
        let stale = open_lock(&path).unwrap();
        stale.write_all_at(b"not a time, and longer\n", 0).unwrap();
        drop(stale);
        let before = now();
        let Lookup::Ours(turn) = lookup_at(&path) else {
            panic!("a free lock is ours");
        };
        let Lookup::Running(watch) = lookup_at(&path) else {
            panic!("a held lock is another lookup's");
        };
        assert!(watch.running());
        assert!(watch.running(), "looking changes nothing");
        let began = watch.began().expect("the lookup wrote when it began");
        assert!((before..=now()).contains(&began), "{began}");
        drop(turn);
        assert!(!watch.running());
        // Looking left nothing held, so the next lookup is ours.
        assert!(matches!(lookup_at(&path), Lookup::Ours(_)));
        assert_eq!(mode(&path), 0o600);
    }
}
