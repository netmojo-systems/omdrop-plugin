//! One receiver: /Discover, /Ask and /Upload, each a POST on one keep-alive
//! TLS connection that is opened on first use and kept until someone replaces
//! it (airdrop-send.py's `AirDropClient`).

use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use omdrop_proto::archive::{CpioWriter, DvzipEncoder};
use omdrop_proto::debugdump;
use plist::{Dictionary, Value};
use rustls::ClientConfig;

use crate::error::PyErr;
use crate::http::{Body, Conn, Endpoint, Response};
use crate::icon::file_icon;
use crate::log::Logger;
use crate::pyfmt::{bytes_repr, list_repr};

/// What every request carries, in this order; a request's own headers replace
/// a value in place (Content-Type) or follow these.
pub const HEADERS: [(&str, &str); 6] = [
    ("Content-Type", "application/octet-stream"),
    ("Connection", "keep-alive"),
    ("Accept", "*/*"),
    ("User-Agent", "AirDrop/1.0"),
    ("Accept-Language", "en-us"),
    ("Accept-Encoding", "br, gzip, deflate"),
];

/// A Mac's /Discover request carries DeviceSupportFlags (and its record
/// data); OpenDrop sends an empty plist. 22:13Z: an Apple-shaped Ask after an
/// empty Discover still produced no UI on an iPhone.
pub const DEVICE_SUPPORT_FLAGS: i64 = 111611;

/// Who we are to a receiver, and the TLS identity that says so.
pub struct Sender {
    pub tls: Arc<ClientConfig>,
    /// The DER validation record belonging to the presented certificate.
    pub record: Option<Vec<u8>>,
    pub computer_name: String,
    pub computer_model: String,
    /// The interface MAC without colons (`SenderID`).
    pub service_id: String,
    /// Link-local addresses without a zone are scoped to this interface.
    pub iface: String,
    /// `--verbose`: redacted protocol dumps.
    pub verbose: bool,
    /// `--auth-tag`: SenderIdentityAuthTag.
    pub auth_tag: Option<Vec<u8>>,
    /// `--should-convert`.
    pub should_convert: bool,
    /// Per-operation socket timeout; `None` blocks (`--op-timeout 0`).
    pub op_timeout: Option<Duration>,
}

/// A file to send: the open file, and the name it travels under.
///
/// Opened once, when the command line is checked, and streamed from that
/// same descriptor at /Upload: a path checked now and reopened later could
/// name a different file by then.
#[derive(Debug)]
pub struct Outgoing {
    pub path: PathBuf,
    pub name: String,
    /// The size when opened, as the Ask announces it. The archive writer
    /// refuses a file that no longer has this many bytes at /Upload.
    pub size: u64,
    pub file: File,
}

impl Outgoing {
    /// Open a file to send. Only regular files (checked on the open
    /// descriptor): the archive carries files, and `FileIsDirectory` is
    /// always false. Symlinks the user names are followed, as before.
    pub fn new(path: &Path) -> io::Result<Outgoing> {
        use std::os::unix::fs::OpenOptionsExt;
        // O_NONBLOCK so naming a FIFO or a device fails here instead of
        // hanging in open(); it changes nothing for a regular file.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)?;
        let meta = file.metadata()?;
        if !meta.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a regular file",
            ));
        }
        Ok(Outgoing {
            path: path.to_owned(),
            name: basename(path),
            size: meta.len(),
            file,
        })
    }
}

/// `os.path.basename`.
pub fn basename(path: &Path) -> String {
    let s = path.to_string_lossy();
    s.rsplit('/').next().unwrap_or(&s).to_owned()
}

/// The UTI a Mac puts in an Ask's `FileType`.
pub fn uti(name: &str) -> &'static str {
    let ext = match name.rfind('.') {
        // os.path.splitext: a leading dot is not an extension.
        Some(i)
            if name
                .get(..i)
                .is_some_and(|stem| !stem.trim_start_matches('.').is_empty()) =>
        {
            name.get(i..).unwrap_or("").to_ascii_lowercase()
        }
        _ => String::new(),
    };
    match ext.as_str() {
        ".jpg" | ".jpeg" => "public.jpeg",
        ".png" => "public.png",
        ".heic" => "public.heic",
        ".mov" => "com.apple.quicktime-movie",
        ".mp4" => "public.mpeg-4",
        ".pdf" => "com.adobe.pdf",
        ".txt" => "public.plain-text",
        _ => "public.data",
    }
}

/// A fresh upper-case UUID4, as `str(uuid.uuid4()).upper()`.
pub fn transfer_id() -> String {
    let mut b = [0u8; 16];
    fill_random(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02X}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

fn fill_random(buf: &mut [u8]) {
    let mut filled = 0;
    while filled < buf.len() {
        let rest = &mut buf[filled..];
        // SAFETY: `rest` is a valid writable buffer of `rest.len()` bytes.
        let n = unsafe { libc::getrandom(rest.as_mut_ptr().cast(), rest.len(), 0) };
        if n > 0 {
            filled += n.unsigned_abs();
        } else if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            // getrandom cannot fail on a supported kernel; a TransferID only
            // needs to be unique, so fall back to the clock rather than abort.
            let t = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            for (i, x) in rest.iter_mut().enumerate() {
                *x = (t >> ((i % 16) * 8)) as u8 ^ (std::process::id() as u8);
            }
            return;
        }
    }
}

fn plist_binary(dict: Dictionary) -> Vec<u8> {
    let mut dict = dict;
    // plistlib sorts keys.
    dict.sort_keys();
    let mut out = Vec::new();
    // Writing a dictionary of plain values into memory cannot fail.
    let _ = Value::Dictionary(dict).to_writer_binary(&mut out);
    out
}

/// Longest peer name kept, in UTF-8 bytes, as for a file name.
pub const PEER_NAME_MAX_BYTES: usize = 255;

/// A peer's `ReceiverComputerName` as Omdrop shows it, or `None` when
/// nothing is left. The name is whatever the device in range chose, and it is
/// printed into `--list` rows, the panel's tiles and logs: a line break forges
/// another row, an escape sequence drives the terminal, bidirectional and
/// zero-width characters disguise one name as another, and nothing bounds
/// its length. Removes C0 and C1 controls, DEL, the line and paragraph
/// separators, bidi embeddings, overrides and isolates, and zero-width
/// characters, then keeps at most [`PEER_NAME_MAX_BYTES`] bytes (whole
/// characters) and trims surrounding whitespace. Omdrop's Python programs
/// apply the same rules.
pub fn clean_peer_name(raw: &str) -> Option<String> {
    let mut name = String::new();
    for c in raw.chars().filter(|&c| {
        !matches!(
            c,
            '\u{0}'..='\u{1f}'
                | '\u{7f}'..='\u{9f}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
                | '\u{feff}'
        )
    }) {
        if name.len() + c.len_utf8() > PEER_NAME_MAX_BYTES {
            break;
        }
        name.push(c);
    }
    let name = name.trim();
    (!name.is_empty()).then(|| name.to_owned())
}

/// One receiver and the connection to it.
pub struct Client<'a> {
    pub sender: &'a Sender,
    pub endpoint: Endpoint,
    pub conn: Option<Conn>,
    pub transfer_id: Option<String>,
    log: &'a Logger,
    /// Caps every operation (name lookups).
    deadline: Option<Instant>,
}

impl<'a> Client<'a> {
    pub fn new(sender: &'a Sender, endpoint: Endpoint, log: &'a Logger) -> Client<'a> {
        Client {
            sender,
            endpoint,
            conn: None,
            transfer_id: None,
            log,
            deadline: None,
        }
    }

    /// Every operation on this client ends by `deadline`.
    pub fn with_deadline(mut self, deadline: Instant) -> Client<'a> {
        self.deadline = Some(deadline);
        self
    }

    /// Open a fresh connection now, replacing any other (the Ask's).
    pub fn reconnect(&mut self) -> io::Result<()> {
        self.conn = None;
        self.conn = Some(Conn::open(
            &self.endpoint,
            &self.sender.tls,
            self.sender.op_timeout,
            self.deadline,
        )?);
        Ok(())
    }

    fn dump(&self, name: &str, data: &[u8]) {
        if let Err(e) = debugdump::dump(name, data, self.sender.verbose) {
            self.log
                .warning("airdrop", &format!("protocol dump skipped: {e}"));
        }
    }

    /// POST and read the whole answer: (status is 200, response body).
    pub fn post(
        &mut self,
        path: &str,
        body: Body<'_>,
        extra: &[(&str, String)],
    ) -> io::Result<(bool, Vec<u8>)> {
        let name = path.trim_matches('/').to_lowercase();
        if let Body::Bytes(b) = &body {
            self.dump(&format!("send_{name}_request.plist"), b);
        }
        self.log.wire(&format!("POST {path}"));
        if self.conn.as_ref().is_none_or(|c| c.closed) {
            self.reconnect()?;
        }
        let mut headers: Vec<(&str, String)> =
            HEADERS.iter().map(|(k, v)| (*k, (*v).to_owned())).collect();
        for (k, v) in extra {
            match headers.iter_mut().find(|(h, _)| h.eq_ignore_ascii_case(k)) {
                Some(slot) => slot.1 = v.clone(),
                None => headers.push((k, v.clone())),
            }
        }
        let host = self.endpoint.host_header();
        let Some(conn) = self.conn.as_mut() else {
            return Err(PyErr::new("NotConnected", "no connection").into_io());
        };
        let result = conn.post(path, &host, &headers, body);
        let Response {
            status,
            reason,
            body,
        } = match result {
            Ok(r) => r,
            Err(e) => {
                // A failed exchange leaves the connection in an unknown state.
                self.conn = None;
                return Err(e);
            }
        };
        self.dump(&format!("send_{name}_response.plist"), &body);
        self.log.wire(&format!("{path} answered {status} {reason}"));
        Ok((status == 200, body))
    }

    /// /Discover: the receiver's name, cleaned by [`clean_peer_name`], or
    /// `None` when it answered without one.
    pub fn discover(&mut self) -> io::Result<Option<String>> {
        let mut body = Dictionary::new();
        body.insert(
            "DeviceSupportFlags".into(),
            Value::Integer(DEVICE_SUPPORT_FLAGS.into()),
        );
        if let Some(record) = &self.sender.record {
            body.insert("SenderRecordData".into(), Value::Data(record.clone()));
        }
        let req = plist_binary(body);
        // The status is not checked, as Python did not: a refusal carries no
        // plist and fails to parse, which is the failure reported.
        let (_, resp) = self.post("/Discover", Body::Bytes(&req), &[])?;
        // Bounded parse: a binary plist's shared references can expand a
        // kilobyte into billions of values, and deep nesting overflows the stack.
        let value = omdrop_proto::safeplist::parse(&resp)
            .map_err(|_| PyErr::new("InvalidFileException", "Invalid file").into_io())?;
        let Value::Dictionary(dict) = value else {
            return Err(
                PyErr::new("AttributeError", "the /Discover answer is not a dictionary").into_io(),
            );
        };
        let mut keys: Vec<&str> = dict.keys().map(String::as_str).collect();
        keys.sort_unstable();
        self.log.send(&format!(
            "{} DISCOVER response keys: {}",
            self.log.t(),
            list_repr(&keys)
        ));
        Ok(match dict.get("ReceiverComputerName") {
            Some(Value::String(s)) => clean_peer_name(s),
            Some(Value::Integer(i)) => Some(i.to_string()),
            _ => None,
        })
    }

    fn ask_common(&mut self, body: &mut Dictionary) {
        if let Some(record) = &self.sender.record {
            body.insert("SenderRecordData".into(), Value::Data(record.clone()));
        }
        // 09-08: a Mac's own Ask carries a 3-byte SenderIdentityAuthTag that
        // binds the HTTP sender to its BLE presence. --auth-tag sets it.
        if let Some(tag) = &self.sender.auth_tag {
            body.insert("SenderIdentityAuthTag".into(), Value::Data(tag.clone()));
        }
    }

    fn post_ask(&mut self, body: Dictionary) -> io::Result<bool> {
        let req = plist_binary(body);
        let (ok, resp) = self.post("/Ask", Body::Bytes(&req), &[])?;
        let head = resp.get(..120).unwrap_or(&resp);
        self.log.send(&format!(
            "{} ASK response {} B: {}",
            self.log.t(),
            resp.len(),
            bytes_repr(head)
        ));
        Ok(ok)
    }

    /// A files Ask, shaped like a Mac's (captured 2026-09-07): TransferID,
    /// TransferType, Items, per-file FileSize, a UTI, and an icon. An iPhone
    /// answered OpenDrop's older shape with no UI at all.
    pub fn ask(&mut self, files: &[Outgoing]) -> io::Result<bool> {
        let entries: Vec<Value> = files
            .iter()
            .map(|f| {
                let mut e = Dictionary::new();
                e.insert("FileName".into(), Value::String(f.name.clone()));
                e.insert("FileType".into(), Value::String(uti(&f.name).into()));
                e.insert("FileSize".into(), Value::Integer(f.size.into()));
                e.insert("FileBomPath".into(), Value::String(format!("./{}", f.name)));
                e.insert("FileIsDirectory".into(), Value::Boolean(false));
                e.insert("ConvertMediaFormats".into(), Value::Boolean(false));
                if self.sender.should_convert {
                    e.insert("ShouldConvertMediaFormats".into(), Value::Boolean(false));
                }
                e.sort_keys();
                Value::Dictionary(e)
            })
            .collect();
        // One TransferID for Ask and Upload: sharingd sends the same UUID in
        // the Ask body and the Upload's TransferID header (093540Z).
        let tid = transfer_id();
        self.transfer_id = Some(tid.clone());
        let mut body = Dictionary::new();
        body.insert(
            "TransferID".into(),
            Value::Dictionary(
                [("id".to_owned(), Value::String(tid))]
                    .into_iter()
                    .collect(),
            ),
        );
        body.insert(
            "TransferType".into(),
            Value::Dictionary(
                [("files".to_owned(), Value::Dictionary(Dictionary::new()))]
                    .into_iter()
                    .collect(),
            ),
        );
        body.insert(
            "SenderID".into(),
            Value::String(self.sender.service_id.clone()),
        );
        body.insert("BundleID".into(), Value::String("com.apple.finder".into()));
        body.insert(
            "SenderComputerName".into(),
            Value::String(self.sender.computer_name.clone()),
        );
        body.insert(
            "SenderModelName".into(),
            Value::String(self.sender.computer_model.clone()),
        );
        body.insert("Items".into(), Value::Array(Vec::new()));
        body.insert("Files".into(), Value::Array(entries));
        body.insert("ConvertMediaFormats".into(), Value::Boolean(false));
        self.ask_common(&mut body);
        if let Some(icon) = files.first().and_then(|f| file_icon(&f.file)) {
            body.insert("FileIcon".into(), Value::Data(icon));
        }
        self.post_ask(body)
    }

    /// A links Ask: the Ask is the whole transfer. Shaped like an iPhone's
    /// (2026-09-12, 2026-09-24): TransferType `links`, the URLs in Items, no
    /// Files, and nothing on /Upload.
    pub fn ask_links(&mut self, urls: &[String]) -> io::Result<bool> {
        let tid = transfer_id();
        self.transfer_id = Some(tid.clone());
        let mut body = Dictionary::new();
        body.insert(
            "TransferID".into(),
            Value::Dictionary(
                [("id".to_owned(), Value::String(tid))]
                    .into_iter()
                    .collect(),
            ),
        );
        body.insert(
            "TransferType".into(),
            Value::Dictionary(
                [("links".to_owned(), Value::Dictionary(Dictionary::new()))]
                    .into_iter()
                    .collect(),
            ),
        );
        body.insert(
            "SenderID".into(),
            Value::String(self.sender.service_id.clone()),
        );
        body.insert("BundleID".into(), Value::String("com.apple.Safari".into()));
        body.insert(
            "SenderComputerName".into(),
            Value::String(self.sender.computer_name.clone()),
        );
        body.insert(
            "SenderModelName".into(),
            Value::String(self.sender.computer_model.clone()),
        );
        body.insert(
            "Items".into(),
            Value::Array(urls.iter().map(|u| Value::String(u.clone())).collect()),
        );
        body.insert("ConvertMediaFormats".into(), Value::Boolean(false));
        self.ask_common(&mut body);
        self.post_ask(body)
    }

    /// sharingd's Upload, as our receiver saw a Mac's (093540Z):
    /// `Content-Type: application/x-dvzip`, `TotalBytes: <sum of file sizes>`,
    /// `TransferID: <the Ask's UUID>`, `Transfer-Encoding: chunked`; the body
    /// is a DVZip-framed cpio (odc) archive of the files, each stored under
    /// its bare name. OpenDrop's x-cpio + gzip is rejected by sharingd (406).
    /// Same TLS connection as the Ask.
    ///
    /// Streamed: a file of any size costs one 64 KiB block of memory, where
    /// the Python sender built the whole archive in memory first.
    pub fn upload(&mut self, files: &[Outgoing]) -> io::Result<bool> {
        let tid = self.transfer_id.clone().unwrap_or_else(transfer_id);
        let total: u64 = files.iter().map(|f| f.size).sum();
        let headers = [
            ("Content-Type", "application/x-dvzip".to_owned()),
            ("TotalBytes", total.to_string()),
            ("TransferID", tid.clone()),
        ];
        let mode = debugdump::mode(self.sender.verbose);
        let mut cpio_bytes = 0u64;
        let mut dvzip_bytes = 0u64;
        let mut kept: Option<Vec<u8>> = (mode == debugdump::Mode::Sensitive).then(Vec::new);
        let log = self.log;
        let mut produce = |w: &mut dyn Write| -> io::Result<()> {
            let wire = Counting {
                inner: Tee {
                    inner: w,
                    copy: kept.as_mut(),
                },
                count: 0,
            };
            let dvzip = DvzipEncoder::new(wire);
            let mut cpio = CpioWriter::new(Counting {
                inner: dvzip,
                count: 0,
            });
            for f in files {
                let mut data = &f.file;
                data.seek(SeekFrom::Start(0))?;
                let meta = f.file.metadata()?;
                cpio.append_file(&f.name, &meta, &mut data)?;
            }
            let counted = cpio.finish()?;
            cpio_bytes = counted.count;
            let wire = counted.inner.finish()?;
            dvzip_bytes = wire.count;
            log.send(&format!(
                "{} UPLOAD {} B dvzip ({} B cpio) TransferID {}",
                log.t(),
                dvzip_bytes,
                cpio_bytes,
                tid
            ));
            Ok(())
        };
        let result = self.post("/Upload", Body::Stream(&mut produce), &headers);
        // The request dump, as Python wrote it: the body itself only when
        // sensitive dumps were asked for, otherwise its size.
        match mode {
            debugdump::Mode::Off => {}
            debugdump::Mode::Sensitive => {
                let body = kept.take().unwrap_or_default();
                self.dump("send_upload_request.plist", &body);
            }
            debugdump::Mode::Redacted => {
                if let Some(root) = std::env::var_os("XDG_RUNTIME_DIR") {
                    let text = format!("<opaque {dvzip_bytes} bytes>");
                    if let Err(e) = debugdump::dump_into(
                        Path::new(&root),
                        "send_upload_request.plist",
                        text.as_bytes(),
                        debugdump::Mode::Sensitive,
                    ) {
                        self.log
                            .warning("airdrop", &format!("protocol dump skipped: {e}"));
                    }
                } else {
                    self.log.warning(
                        "airdrop",
                        "protocol dump skipped: protocol dumps require XDG_RUNTIME_DIR",
                    );
                }
            }
        }
        result.map(|(ok, _)| ok)
    }
}

/// Counts bytes on their way through.
struct Counting<W: Write> {
    inner: W,
    count: u64,
}

impl<W: Write> Write for Counting<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.count += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Copies bytes into a buffer on their way through (sensitive upload dump).
struct Tee<'w, 'k> {
    inner: &'w mut dyn Write,
    copy: Option<&'k mut Vec<u8>>,
}

impl Write for Tee<'_, '_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        if let Some(copy) = self.copy.as_mut() {
            copy.extend_from_slice(buf.get(..n).unwrap_or_default());
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utis_follow_the_extension() {
        assert_eq!(uti("photo.JPG"), "public.jpeg");
        assert_eq!(uti("clip.mov"), "com.apple.quicktime-movie");
        assert_eq!(uti(".txt"), "public.data");
        assert_eq!(uti("archive.tar.gz"), "public.data");
        assert_eq!(uti("README"), "public.data");
    }

    #[test]
    fn transfer_ids_are_upper_case_uuid4s() {
        let a = transfer_id();
        assert_eq!(a.len(), 36);
        assert_eq!(a, a.to_uppercase());
        assert_eq!(&a[14..15], "4");
        assert!(matches!(&a[19..20], "8" | "9" | "A" | "B"));
        assert_ne!(a, transfer_id());
    }

    #[test]
    fn only_regular_files_are_sent() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Outgoing::new(dir.path()).is_err());
        let f = dir.path().join("a b.txt");
        std::fs::write(&f, b"hello").unwrap();
        let o = Outgoing::new(&f).unwrap();
        assert_eq!((o.name.as_str(), o.size), ("a b.txt", 5));
        assert!(Outgoing::new(&dir.path().join("missing")).is_err());
    }

    #[test]
    fn the_file_checked_is_the_file_sent() {
        use std::io::Read;
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("photo.jpg");
        std::fs::write(&f, b"the original").unwrap();
        let o = Outgoing::new(&f).unwrap();
        // The path is swapped after the check; the open file is not.
        let other = dir.path().join("other");
        std::fs::write(&other, b"something else entirely").unwrap();
        std::fs::rename(&other, &f).unwrap();
        let mut got = Vec::new();
        (&o.file).read_to_end(&mut got).unwrap();
        assert_eq!(got, b"the original");
    }

    #[test]
    fn a_fifo_is_refused_without_hanging() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("pipe");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let err = Outgoing::new(&fifo).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
