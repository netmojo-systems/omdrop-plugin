//! Apple Continuity AirDrop (type 0x05) BLE advertisement (`ble-airdrop-adv.py`).
//!
//! WHY. Measured against a Mac with Finder > AirDrop open for 4 min 35 s: it
//! published no `_airdrop._tcp` in its MIFs until a sender's BLE AirDrop
//! advert appeared, then published it 1.13 s later. The BLE advert gates a
//! Mac's AirDrop publication; without one our sender has nothing to browse.
//! This is the sender-side half: the wake.
//!
//! WHAT GOES ON AIR. Manufacturer Specific Data, company 0x004C (Apple), value
//! one Continuity TLV `05 12 <18 bytes>`. Arms, read off the air on 09-07:
//!
//! ```text
//! A  (OS 26 shape)     40 xx xx xx | 00 00 00 00 | 03 | 4 x 2-byte hashes | 00
//! V2 (iPhone, 2025-08) 00 x8                     | 02 | 4 x 2-byte hashes | 00
//! B  (published shape) 00 x8                     | 01 | 4 x 2-byte hashes | 00
//! ```
//!
//! The three `xx` bytes vary per device; real Macs rotate them with the
//! address. Hashes are truncated SHA-256 of the sender's contact identifiers;
//! zeros mean "no contact match", which only a receiver in Everyone mode
//! accepts.
//!
//! MECHANICS. BlueZ `LEAdvertisement1` over D-Bus (bluetoothd owns the
//! controller; raw HCI would fight it). `ManufacturerData` is keyed by company
//! id and the value starts at the TLV type byte. The advertising address is
//! whatever the adapter uses, reported at start so a run's notes carry it.
//!
//! Prints `<epoch> <HH:MM:SSZ> START|STOP ...` lines, flushed, so `ble-adv.log`
//! lines up with `af.log`. `send-to-peer` waits for ` START ` and treats a line
//! with `FAILED` as a failed wake.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use omdrop_identity::{Identity, IdentityError};
use zbus::blocking::Connection;
use zbus::zvariant::{ObjectPath, OwnedValue, Value};

use crate::clock;

pub const APPLE: u16 = 0x004c;
pub const AD_IFACE: &str = "org.bluez.LEAdvertisement1";
pub const ADM_IFACE: &str = "org.bluez.LEAdvertisingManager1";
pub const ADAPTER_IFACE: &str = "org.bluez.Adapter1";
pub const ADV_PATH: &str = "/org/omarchy/airdrop/adv0";
/// A disk record larger than this is not a validation record.
const RECORD_MAX: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arm {
    A,
    V2,
    B,
}

impl Arm {
    pub fn parse(text: &str) -> Option<Arm> {
        match text {
            "A" => Some(Arm::A),
            "V2" => Some(Arm::V2),
            "B" => Some(Arm::B),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Arm::A => "A",
            Arm::V2 => "V2",
            Arm::B => "B",
        }
    }
}

/// Python `bytes.fromhex`: pairs of hex digits, ASCII whitespace allowed
/// between pairs.
pub fn fromhex(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 2);
    let mut bytes = text.bytes();
    while let Some(b) = bytes.next() {
        if b.is_ascii_whitespace() {
            continue;
        }
        let hi = char::from(b).to_digit(16)?;
        let lo = char::from(bytes.next()?).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The Continuity TLV: `<type> <len=18> <body>`.
pub fn payload(arm: Arm, tlv_type: u8, hashes: &str, tag: &str) -> Result<Vec<u8>, String> {
    let h = fromhex(hashes)
        .filter(|h| h.len() == 8)
        .ok_or("--hashes must be 8 bytes (four 2-byte hashes) as hex")?;
    let t = fromhex(tag)
        .filter(|t| t.len() == 3)
        .ok_or("--tag must be 3 bytes as hex")?;
    let mut body = Vec::with_capacity(18);
    match arm {
        // OS 26 shape: 40 <tag> 00000000 03 hashes 00 (the 3 tag bytes rotate
        // with the address on real Macs).
        Arm::A => {
            body.push(0x40);
            body.extend_from_slice(&t);
            body.extend_from_slice(&[0; 4]);
            body.push(0x03);
        }
        // iPhone, Aug 2025 (NetSPI report): 00x8 02 hashes 00.
        Arm::V2 => {
            body.extend_from_slice(&[0; 8]);
            body.push(0x02);
        }
        // Published 2019/2020 shape: 00x8 01 hashes 00.
        Arm::B => {
            body.extend_from_slice(&[0; 8]);
            body.push(0x01);
        }
    }
    body.extend_from_slice(&h);
    body.push(0);
    let mut value = vec![tlv_type, body.len() as u8];
    value.extend(body);
    Ok(value)
}

/// The advert as hex with the contact-hash bytes masked.
///
/// Every arm puts the four 2-byte hashes at value[11..19], so one slice covers
/// them. Shape, arm, tag, length and the trailing byte stay visible, because a
/// capture is compared against those; the hashes do not, because a 2-byte
/// prefix narrows a phone number and this string goes into a log that
/// outlives the run. Zeros are shown: they identify nobody, and seeing them is
/// how the old zero-hash behaviour was caught.
pub fn redact(value: &[u8]) -> String {
    let h = hex(value);
    let slots = h.get(22..38.min(h.len())).unwrap_or("");
    if !slots.is_empty() && slots.bytes().all(|b| b == b'0') {
        return h;
    }
    format!(
        "{}{}{}",
        h.get(..22).unwrap_or(&h),
        "xx".repeat(8),
        h.get(38..).unwrap_or("")
    )
}

fn falsy(v: &plist::Value) -> bool {
    match v {
        plist::Value::Boolean(b) => !b,
        plist::Value::String(s) => s.is_empty(),
        plist::Value::Data(d) => d.is_empty(),
        plist::Value::Array(a) => a.is_empty(),
        plist::Value::Dictionary(d) => d.is_empty(),
        plist::Value::Integer(i) => i.as_signed() == Some(0) || i.as_unsigned() == Some(0),
        plist::Value::Real(r) => *r == 0.0,
        _ => false,
    }
}

/// The four 2-byte contact hashes from a validation record's plist, as hex,
/// and how many identifiers the record validates.
///
/// `ValidatedEmailHashes`/`ValidatedPhoneHashes` are full SHA-256 of the
/// identifiers Apple verified for the account; the advert carries the first
/// two bytes of each. Nothing here prints a hash: a full hash is reversible to
/// a phone number by brute force, and a prefix narrows one.
pub fn hashes_from_plist(data: &[u8]) -> Result<(String, usize), String> {
    let bad = |why: String| format!("cannot read validation record: {why}");
    // Bounded: `--hashes-from-record PATH` reads any file it is given.
    let value = omdrop_identity::safeplist::parse(data).map_err(|e| bad(e.to_string()))?;
    let dict = value
        .as_dictionary()
        .ok_or_else(|| bad("not a dictionary".into()))?;
    let prefixes = |key: &str| -> Result<Vec<String>, String> {
        match dict.get(key) {
            None => Ok(Vec::new()),
            Some(v) if falsy(v) => Ok(Vec::new()),
            Some(plist::Value::Array(items)) => Ok(items
                .iter()
                .filter_map(|i| i.as_string())
                .map(|h| h.to_lowercase().chars().take(4).collect())
                .collect()),
            Some(_) => Err(bad(format!("{key} is not a list"))),
        }
    };
    let emails = prefixes("ValidatedEmailHashes")?;
    let phones = prefixes("ValidatedPhoneHashes")?;
    if emails.is_empty() && phones.is_empty() {
        return Err("validation record validates no identifiers; nothing to advertise".into());
    }
    // Slot order follows the genuine advert measured off the air on 2026-09-19:
    // slot 0 email, 1 phone, 2 the account's DSID hash, 3 email. The DSID hash
    // is not in the record and cannot be derived from it, so slot 2 carries
    // another email. That device advertised a rotating subset of its
    // identifiers, and the wake proven on 2026-09-19 needed only a match, not
    // a particular slot.
    let slots = [emails.first(), phones.first(), emails.get(1), emails.get(2)];
    // Spare identifiers of either kind fill an empty slot rather than a zero
    // the receiver cannot match.
    let mut spare = emails.iter().skip(3).chain(phones.iter().skip(1));
    let out: String = slots
        .into_iter()
        .map(|slot| slot.or_else(|| spare.next()).map_or("0000", |s| s.as_str()))
        .collect();
    Ok((out, emails.len() + phones.len()))
}

/// The record's signed content, without checking the signature: identity
/// publication validates it, and the bytes never touch the disk here.
fn cms_content(record: &[u8]) -> Result<Vec<u8>, String> {
    let bad = |why: String| format!("cannot read validation record: {why}");
    let mut child = Command::new("openssl")
        .args(["cms", "-verify", "-noverify", "-inform", "DER"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| bad(format!("openssl: {e}")))?;
    let stdin = child.stdin.take();
    let data = record.to_vec();
    // Written from a thread so a large stdout can never deadlock against us.
    let writer = std::thread::spawn(move || {
        if let Some(mut s) = stdin {
            let _ = s.write_all(&data);
        }
    });
    let out = child
        .wait_with_output()
        .map_err(|e| bad(format!("openssl: {e}")))?;
    let _ = writer.join();
    if !out.status.success() {
        return Err(bad(String::from_utf8_lossy(&out.stderr).trim().to_owned()));
    }
    Ok(out.stdout)
}

/// [`hashes_from_plist`] over a DER validation record.
pub fn hashes_from_record(record: &[u8]) -> Result<(String, usize), String> {
    hashes_from_plist(&cms_content(record)?)
}

/// The invoking user's disk record, used only by the explicit research
/// override `--hashes-from-record` with no path.
pub fn default_record() -> Result<PathBuf, String> {
    // SAFETY: getuid cannot fail.
    let mut uid = unsafe { libc::getuid() };
    if uid == 0 {
        for var in ["PKEXEC_UID", "SUDO_UID"] {
            let value = std::env::var(var).unwrap_or_default();
            if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
                uid = value
                    .parse()
                    .map_err(|_| format!("{var} is not a user id"))?;
                break;
            }
        }
    }
    let home = home_of(uid).ok_or_else(|| format!("no home directory for uid {uid}"))?;
    Ok(home.join(".omdrop/keys/validation_record.cms"))
}

fn home_of(uid: libc::uid_t) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    let mut buf = vec![0u8; 16 * 1024];
    // SAFETY: passwd is plain old data; all-zero is a valid value.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the call and `buf` is as long as stated;
    // getpwuid_r stores strings only inside `buf`.
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            &mut pwd,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() || pwd.pw_dir.is_null() {
        return None;
    }
    // SAFETY: getpwuid_r succeeded, so pw_dir is a NUL-terminated string in `buf`.
    let dir = unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) };
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes())))
}

/// Three random bytes as hex: the default arm-A tag.
pub fn random_tag() -> Result<String, String> {
    let mut b = [0u8; 3];
    // SAFETY: `b` is a valid writable buffer of the length passed.
    let n = unsafe { libc::getrandom(b.as_mut_ptr().cast(), b.len(), 0) };
    if n != 3 {
        return Err(format!("getrandom: {}", std::io::Error::last_os_error()));
    }
    Ok(hex(&b))
}

/// Writes timestamped lines, flushed, from any thread.
#[derive(Clone)]
pub struct Stamper(Arc<Mutex<Box<dyn Write + Send>>>);

impl Stamper {
    pub fn new(out: Box<dyn Write + Send>) -> Self {
        Stamper(Arc::new(Mutex::new(out)))
    }

    pub fn stdout() -> Self {
        Stamper::new(Box::new(std::io::stdout()))
    }

    pub fn stamp(&self, msg: &str) {
        let now = clock::epoch_now();
        let line = format!("{now:.3} {} {msg}\n", clock::hms_utc(now));
        let mut out = match self.0.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let _ = out.write_all(line.as_bytes());
        let _ = out.flush();
    }
}

/// The parsed `ble` command line.
#[derive(Clone, Debug)]
pub struct BleOptions {
    pub arm: Arm,
    pub tag: Option<String>,
    /// `--type` as given, printed back in `START`.
    pub type_text: String,
    pub tlv_type: u8,
    pub hashes: Option<String>,
    /// `--hashes-from-record`: `Some(None)` bare (the default record).
    pub hashes_from_record: Option<Option<PathBuf>>,
    pub seconds: u32,
    pub interval_ms: u32,
    pub broadcast: bool,
    pub adapter: String,
}

impl Default for BleOptions {
    fn default() -> Self {
        BleOptions {
            arm: Arm::A,
            tag: None,
            type_text: "0x05".into(),
            tlv_type: 0x05,
            hashes: None,
            hashes_from_record: None,
            seconds: 120,
            interval_ms: 100,
            broadcast: false,
            adapter: "hci0".into(),
        }
    }
}

/// What goes on air, decided before any D-Bus traffic.
#[derive(Clone, Debug)]
pub struct Prepared {
    pub value: Vec<u8>,
    pub tag: String,
}

/// Choose the hashes and build the advert. Identity errors stop here, before
/// BlueZ is contacted: a failed identity must never advertise zero hashes
/// in its place.
pub fn prepare(
    opts: &BleOptions,
    resolve: &dyn Fn() -> Result<Identity, IdentityError>,
    warn: &mut dyn Write,
    stamper: &Stamper,
) -> Result<Prepared, String> {
    let given = opts.hashes.as_deref().filter(|h| !h.is_empty());
    // An empty path was falsy to the Python original: no override at all.
    let record_override = match &opts.hashes_from_record {
        Some(Some(p)) if p.as_os_str().is_empty() => None,
        Some(p) => Some(p.clone()),
        None => None,
    };
    if given.is_some() && record_override.is_some() {
        return Err("--hashes and --hashes-from-record are mutually exclusive".into());
    }
    let mut hashes = opts.hashes.clone();
    let mut identifiers = 0;
    if let Some(path) = record_override {
        let path = match path {
            Some(p) => p,
            // Root reading a path under a user's home follows whatever
            // symlinks that user planted there. The identity resolver reads
            // user files from a child running as the user; this research
            // override does not, so as root it takes only an explicit path.
            // SAFETY: geteuid cannot fail.
            None if unsafe { libc::geteuid() } == 0 => {
                return Err("--hashes-from-record needs an explicit PATH when run as root".into());
            }
            None => default_record()?,
        };
        if path.exists() {
            let record = read_capped(&path)?;
            let (h, n) = hashes_from_record(&record)?;
            hashes = Some(h);
            identifiers = n;
        } else {
            // A self-signed machine has no record and cannot do Contacts Only
            // anyway; it can still wake a receiver set to Everyone, so this
            // degrades rather than refusing to advertise.
            stamper.stamp(&format!(
                "no validation record at {}; advertising zero hashes",
                path.display()
            ));
        }
    } else if hashes.is_none() {
        let identity = resolve().map_err(|e| format!("identity error: {e}"))?;
        for w in &identity.warnings {
            let _ = writeln!(warn, "omdrop-adv ble: RuntimeWarning: {w}");
        }
        if let Some(record) = &identity.record {
            let (h, n) = hashes_from_record(record)?;
            hashes = Some(h);
            identifiers = n;
        }
    }
    let hashes = hashes
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "00".repeat(8));
    let tag = match &opts.tag {
        Some(t) => t.clone(),
        None => random_tag()?,
    };
    let value = payload(opts.arm, opts.tlv_type, &hashes, &tag)?;
    // As in the original, explicit --hashes report as "zeros": only a record
    // says how many identifiers it validates.
    stamper.stamp(&if identifiers > 0 {
        format!("contact hashes: record, {identifiers} identifiers validated, 4 slots filled")
    } else {
        "contact hashes: zeros -- a Contacts Only receiver cannot match these".to_owned()
    });
    Ok(Prepared { value, tag })
}

fn read_capped(path: &Path) -> Result<Vec<u8>, String> {
    let mut data = Vec::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(RECORD_MAX + 1).read_to_end(&mut data))
        .map_err(|e| {
            format!(
                "cannot read {}: {}",
                path.display(),
                crate::rawsock::os_error_text(&e)
            )
        })?;
    if data.len() as u64 > RECORD_MAX {
        return Err(format!(
            "{}: larger than {RECORD_MAX} bytes",
            path.display()
        ));
    }
    Ok(data)
}

/// The `org.bluez.LEAdvertisement1` object BlueZ reads the advert from.
pub struct Advertisement {
    kind: &'static str,
    value: Vec<u8>,
    interval_ms: u32,
    stamper: Stamper,
}

#[zbus::interface(name = "org.bluez.LEAdvertisement1")]
impl Advertisement {
    fn release(&self) {
        self.stamper.stamp("RELEASED by bluetoothd");
    }

    #[zbus(property, name = "Type")]
    fn kind(&self) -> String {
        self.kind.to_owned()
    }

    #[zbus(property)]
    fn manufacturer_data(&self) -> HashMap<u16, OwnedValue> {
        let mut map = HashMap::new();
        if let Ok(v) = OwnedValue::try_from(Value::from(self.value.clone())) {
            map.insert(APPLE, v);
        }
        map
    }

    #[zbus(property)]
    fn includes(&self) -> Vec<String> {
        Vec::new()
    }

    #[zbus(property)]
    fn min_interval(&self) -> u32 {
        self.interval_ms
    }

    #[zbus(property)]
    fn max_interval(&self) -> u32 {
        self.interval_ms
    }
}

/// What ends the wait: a stop signal, or the outcome of registration.
#[derive(Debug)]
pub enum Event {
    Signal,
    Registered,
    RegisterFailed(String),
}

/// A D-Bus error the way dbus-python prints one: `name: message`.
pub fn dbus_error_text(e: &zbus::Error) -> String {
    match e {
        zbus::Error::MethodError(name, Some(detail), _) => format!("{}: {detail}", name.as_str()),
        zbus::Error::MethodError(name, None, _) => name.as_str().to_owned(),
        other => other.to_string(),
    }
}

/// Whether `name` can be a D-Bus object path element (`/org/bluez/<name>`).
pub fn valid_adapter(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn adapter_get(conn: &Connection, path: &str, name: &str) -> Result<OwnedValue, String> {
    let reply = conn
        .call_method(
            Some("org.bluez"),
            path,
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &(ADAPTER_IFACE, name),
        )
        .map_err(|e| format!("{path} {name}: {}", dbus_error_text(&e)))?;
    reply
        .body()
        .deserialize::<OwnedValue>()
        .map_err(|e| format!("{path} {name}: {}", dbus_error_text(&e)))
}

/// Register the advert with BlueZ, keep it up for `opts.seconds` or until a
/// stop signal, then unregister it. Returns the exit status.
///
/// `events` carries [`Event::Signal`] from the caller's signal thread; this
/// function adds the registration outcome to it.
pub fn advertise(
    conn: &Connection,
    opts: &BleOptions,
    prep: &Prepared,
    events: (Sender<Event>, Receiver<Event>),
    stamper: &Stamper,
) -> Result<i32, String> {
    let (tx, rx) = events;
    if !valid_adapter(&opts.adapter) {
        return Err(format!("invalid adapter name {:?}", opts.adapter));
    }
    let path = format!("/org/bluez/{}", opts.adapter);
    let powered = bool::try_from(adapter_get(conn, &path, "Powered")?)
        .map_err(|e| format!("{path} Powered: {e}"))?;
    if !powered {
        conn.call_method(
            Some("org.bluez"),
            path.as_str(),
            Some("org.freedesktop.DBus.Properties"),
            "Set",
            &(ADAPTER_IFACE, "Powered", Value::from(true)),
        )
        .map_err(|e| format!("{path} Powered: {}", dbus_error_text(&e)))?;
    }
    let addr = String::try_from(adapter_get(conn, &path, "Address")?)
        .map_err(|e| format!("{path} Address: {e}"))?;
    let addr_type = String::try_from(adapter_get(conn, &path, "AddressType")?)
        .map_err(|e| format!("{path} AddressType: {e}"))?;

    let adv = Advertisement {
        kind: if opts.broadcast {
            "broadcast"
        } else {
            "peripheral"
        },
        value: prep.value.clone(),
        interval_ms: opts.interval_ms,
        stamper: stamper.clone(),
    };
    conn.object_server()
        .at(ADV_PATH, adv)
        .map_err(|e| format!("cannot serve {ADV_PATH}: {}", dbus_error_text(&e)))?;

    // Registration runs on its own thread so a stop signal is honoured while
    // BlueZ is still deciding. The connection's method timeout bounds it.
    // `_hold` keeps the channel open after that thread ends, so only the
    // deadline or a signal ends the wait below.
    let _hold = tx.clone();
    {
        let conn = conn.clone();
        let path = path.clone();
        std::thread::spawn(move || {
            let empty: HashMap<&str, Value<'_>> = HashMap::new();
            let event = match ObjectPath::try_from(ADV_PATH) {
                Ok(adv_path) => match conn.call_method(
                    Some("org.bluez"),
                    path.as_str(),
                    Some(ADM_IFACE),
                    "RegisterAdvertisement",
                    &(adv_path, empty),
                ) {
                    Ok(_) => Event::Registered,
                    Err(e) => Event::RegisterFailed(dbus_error_text(&e)),
                },
                Err(e) => Event::RegisterFailed(e.to_string()),
            };
            let _ = tx.send(event);
        });
    }

    let status = match rx.recv() {
        Ok(Event::Registered) => {
            stamper.stamp(&format!(
                "START arm={} tag={} type={} interval_ms={} {} adapter_addr={addr} ({addr_type}) mfr=4c00 value={}",
                opts.arm.as_str(),
                prep.tag,
                opts.type_text,
                opts.interval_ms,
                if opts.broadcast { "non-connectable" } else { "connectable" },
                redact(&prep.value),
            ));
            let deadline = Instant::now().checked_add(Duration::from_secs(u64::from(opts.seconds)));
            loop {
                let got = match deadline {
                    Some(d) => rx.recv_timeout(d.saturating_duration_since(Instant::now())),
                    None => rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
                };
                match got {
                    Ok(Event::Signal) | Err(RecvTimeoutError::Timeout) => break,
                    Ok(_) => continue,
                    // Unreachable while `_hold` lives; never spin on it.
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            }
            let unregister = ObjectPath::try_from(ADV_PATH)
                .map_err(zbus::Error::from)
                .and_then(|p| {
                    conn.call_method(
                        Some("org.bluez"),
                        path.as_str(),
                        Some(ADM_IFACE),
                        "UnregisterAdvertisement",
                        &(p,),
                    )
                });
            if let Err(e) = unregister {
                stamper.stamp(&format!("unregister failed: {}", dbus_error_text(&e)));
            }
            stamper.stamp("STOP advertisement unregistered");
            0
        }
        Ok(Event::RegisterFailed(e)) => {
            stamper.stamp(&format!("REGISTER FAILED {e}"));
            0
        }
        // A stop before BlueZ answered: nothing is registered to remove.
        Ok(Event::Signal) | Err(_) => 0,
    };
    let _ = conn.object_server().remove::<Advertisement, _>(ADV_PATH);
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction_masks_only_nonzero_hash_slots() {
        let v = payload(Arm::A, 5, "0102030405060708", "aabbcc").unwrap();
        assert_eq!(redact(&v), "051240aabbcc0000000003xxxxxxxxxxxxxxxx00");
        let z = payload(Arm::B, 5, "0000000000000000", "aabbcc").unwrap();
        assert_eq!(redact(&z), hex(&z));
        assert_eq!(redact(&[1, 2]), "0102xxxxxxxxxxxxxxxx");
    }

    #[test]
    fn fromhex_matches_python() {
        assert_eq!(fromhex("01 02\t0a"), Some(vec![1, 2, 10]));
        assert_eq!(fromhex("0 1"), None);
        assert_eq!(fromhex("012"), None);
        assert_eq!(fromhex("zz"), None);
        assert_eq!(fromhex("é0"), None);
        assert_eq!(fromhex(""), Some(vec![]));
    }

    #[test]
    fn adapter_names_are_object_path_elements() {
        assert!(valid_adapter("hci0"));
        for bad in ["", "hci0/x", "../x", "hci-0", "hci 0"] {
            assert!(!valid_adapter(bad), "{bad:?}");
        }
    }

    #[test]
    fn hashes_reject_records_that_are_not_dictionaries_of_lists() {
        let not_dict = br#"<?xml version="1.0"?><plist version="1.0"><array/></plist>"#;
        assert!(
            hashes_from_plist(not_dict)
                .unwrap_err()
                .contains("not a dictionary")
        );
        let not_list = br#"<?xml version="1.0"?><plist version="1.0"><dict><key>ValidatedEmailHashes</key><string>abcd</string></dict></plist>"#;
        assert!(
            hashes_from_plist(not_list)
                .unwrap_err()
                .contains("is not a list")
        );
        assert!(
            hashes_from_plist(b"garbage")
                .unwrap_err()
                .starts_with("cannot read validation record")
        );
    }

    #[test]
    fn a_record_that_expands_past_its_size_is_refused() {
        let mut dict = plist::Dictionary::new();
        dict.insert(
            "ValidatedEmailHashes".into(),
            plist::Value::Array(vec!["abcd".into()]),
        );
        dict.insert(
            "Pad".into(),
            plist::Value::Array(vec![plist::Value::Data(vec![0x41; 30_000]); 1_000]),
        );
        let mut bomb = Vec::new();
        plist::Value::Dictionary(dict)
            .to_writer_binary(&mut bomb)
            .unwrap();
        // About 32 KB, decoding to 30 MB.
        assert!(bomb.len() < 64 << 10);
        let err = hashes_from_plist(&bomb).unwrap_err();
        assert!(err.starts_with("cannot read validation record: "), "{err}");
    }

    #[test]
    fn unreadable_cms_is_a_clear_error() {
        let err = hashes_from_record(b"not der").unwrap_err();
        assert!(err.starts_with("cannot read validation record: "), "{err}");
    }
}
