//! AirDrop's receiving endpoints, as sharingd (AirDrop/1.0, macOS 15) and iOS
//! actually send them:
//!
//! - `/Discover` and `/Ask` arrive chunked with no Content-Length, so their
//!   bodies go through the same bounded reader as an upload's. Each body is
//!   read from the connection exactly once, in place: Ask and Upload share one
//!   TLS connection, and a swapped-out reader once made the keep-alive loop see
//!   EOF.
//! - `/Upload` arrives as `application/x-dvzip` and is decoded while it streams.
//!   iOS 16 labels the same compressed archive `application/x-cpio`
//!   (plugin #40); that body is decoded alike.
//!
//! Anything else POSTed is answered 400, GET and HEAD a bare 200, and every
//! other method 501. One thread per connection, because sharingd opens several
//! at once and a stalled one must not hold `/Discover` behind it.

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use omdrop_proto::archive::{
    self, ArchiveError, ExtractLimits, ExtractProgress, IO_CHUNK_BYTES, MAX_ARCHIVE_MEMBERS,
    Partials, open_new, py_bytes_repr, py_repr, safe_name,
};
use omdrop_proto::contacts::{self, Apple, AppleChecks, Detail, Outcome, Visibility};
use omdrop_proto::http::{
    self, BodyError, BodyReader, HeadError, MAX_METADATA_BYTES, Patience, READ_IDLE_TIMEOUT,
    ReadDeadline, Request,
};
use omdrop_proto::{debugdump, safeplist, tls};
use plist::{Dictionary, Value};
use rustls::pki_types::CertificateDer;
use rustls::{ServerConfig, ServerConnection, StreamOwned};

use crate::log::{debug, error, info, warning};

/// Free space an upload must leave on the download disk.
pub const MIN_FREE_BYTES: u64 = 1 << 30;
pub const MAX_CONCURRENT_UPLOADS: usize = 2;
/// Connections served at once. sharingd opens a handful; this bounds threads,
/// not transfers. When it is reached, the connection that has waited longest
/// for its handshake or its next request is closed to make room, so slow or
/// silent connections can never lock real senders out.
pub const MAX_CONNECTIONS: usize = 64;
/// Connections one peer address may hold at once.
pub const MAX_CONNECTIONS_PER_PEER: usize = 8;
/// The whole TLS handshake, and each request head, must arrive within this:
/// a peer trickling one byte every 25 s would otherwise hold a connection for
/// days under the 30 s idle timeout alone.
pub const HEAD_DEADLINE: Duration = Duration::from_secs(30);
/// `ReceiverMediaCapabilities`, in both the Discover and the Ask answer: the
/// version 3 codec and profile table a MacBook Pro sends, byte for byte as
/// the plugin's receiver has advertised it since 0.16.0. With it, an iPhone
/// sends photos and videos in their original formats (HEIC, HEVC); with the
/// codec-free `{"Version": 1}` it converted them to JPEG and H.264 first
/// (R6, 2026-10-14).
const MEDIA_CAPABILITIES: &[u8] = include_bytes!("media-capabilities.json");

/// Uploads in progress, removed if the receiver is stopped mid-upload.
pub static PARTIALS: Partials = Partials::new();

type Io = BufReader<StreamOwned<ServerConnection, Sock>>;

/// How long an accepted Ask waits for its Upload on the same connection
/// (plugin a800d74). The sender uploads straight after the Ask is answered,
/// but a poor AWDL link can delay that request past the idle limit; 60 s
/// covers the roughly 45 s a Mac sender has been seen waiting. Only the wait
/// for the next request's first byte gets this.
pub const UPLOAD_WAIT: Duration = Duration::from_secs(60);
/// The step an upload waits in at a chunk boundary before asking whether the
/// archive is already whole (plugin #41; [`Patience`]).
pub const UPLOAD_STEP: Duration = Duration::from_secs(3);
/// After an upload answered without its closing chunk: read what the sender
/// still has in flight until it closes or goes quiet this long (plugin #47)...
pub const DRAIN_QUIET: Duration = Duration::from_secs(1);
/// ...and never for longer than this in all.
pub const DRAIN_LIMIT: Duration = Duration::from_secs(10);

/// Connection limits; tests shrink them.
#[derive(Clone, Copy, Debug)]
pub struct ConnLimits {
    pub max_connections: usize,
    pub max_per_peer: usize,
    pub head_deadline: Duration,
    /// How long a read waits for any byte before the request is given up.
    pub idle_timeout: Duration,
    pub upload_wait: Duration,
    pub upload_step: Duration,
    pub drain_quiet: Duration,
    pub drain_limit: Duration,
}

impl Default for ConnLimits {
    fn default() -> Self {
        ConnLimits {
            max_connections: MAX_CONNECTIONS,
            max_per_peer: MAX_CONNECTIONS_PER_PEER,
            head_deadline: HEAD_DEADLINE,
            idle_timeout: READ_IDLE_TIMEOUT,
            upload_wait: UPLOAD_WAIT,
            upload_step: UPLOAD_STEP,
            drain_quiet: DRAIN_QUIET,
            drain_limit: DRAIN_LIMIT,
        }
    }
}

/// A connection's socket. Each read waits at most the idle timeout for
/// data, or the override while one is set, and while a deadline is set (the
/// TLS handshake, a request head) no longer than what is left of it.
pub struct Sock {
    inner: TcpStream,
    idle: Duration,
    /// Replaces `idle` while non-zero, in milliseconds. Shared, so a reader
    /// that holds the connection (an upload's [`Patience`]) can set it.
    wait: Arc<AtomicU64>,
    deadline: Option<Instant>,
    timeout: Option<Duration>,
}

impl Sock {
    fn new(inner: TcpStream, idle: Duration) -> Self {
        Sock {
            inner,
            idle,
            wait: Arc::new(AtomicU64::new(0)),
            deadline: None,
            timeout: None,
        }
    }

    /// Override the idle wait (`Some`) or restore it (`None`).
    fn set_wait(&self, wait: Option<Duration>) {
        set_wait(&self.wait, wait);
    }
}

fn set_wait(cell: &AtomicU64, wait: Option<Duration>) {
    let ms = wait.map_or(0, |d| {
        u64::try_from(d.as_millis()).unwrap_or(u64::MAX).max(1)
    });
    cell.store(ms, Ordering::Relaxed);
}

impl Read for Sock {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let base = match self.wait.load(Ordering::Relaxed) {
            0 => self.idle,
            ms => Duration::from_millis(ms),
        };
        let wait = match self.deadline {
            None => base,
            Some(deadline) => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "timed out"));
                }
                left.clamp(Duration::from_millis(1), base)
            }
        };
        if self.timeout != Some(wait) {
            self.inner.set_read_timeout(Some(wait))?;
            self.timeout = Some(wait);
        }
        self.inner.read(buf)
    }
}

impl Write for Sock {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.inner.write(data)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// An open connection, as the accept loop sees it.
struct Live {
    sock: TcpStream,
    ip: IpAddr,
    /// Since when it has been waiting for its handshake or next request
    /// head; `None` while a request is being served.
    waiting_since: Option<Instant>,
}

/// Everything a request needs, fixed at start.
pub struct Settings {
    pub name: String,
    pub model: String,
    pub dest: PathBuf,
    pub max_receive_percent: u64,
    /// This machine's Apple ID validation record, if it has one.
    pub record: Option<Vec<u8>>,
    /// `OMDROP_PEERCERT`: save every client certificate here, for research.
    pub peercert_dir: Option<PathBuf>,
    /// Re-read on every request.
    pub visibility_path: PathBuf,
    pub known_senders_path: PathBuf,
    pub min_free_bytes: u64,
    pub limits: ConnLimits,
}

pub struct Server {
    settings: Settings,
    tls: Arc<ServerConfig>,
    apple: Box<dyn AppleChecks + Send + Sync>,
    live: Mutex<HashMap<u64, Live>>,
    next_id: AtomicU64,
    uploads: AtomicUsize,
    /// Held by a links Ask from its budget check through its last write.
    links: Mutex<()>,
}

/// The peer's address as Python printed it: link-local with its zone.
fn host(addr: &SocketAddr) -> String {
    match addr {
        SocketAddr::V6(v6) if v6.scope_id() != 0 => {
            let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
            // SAFETY: `name` has IF_NAMESIZE bytes, as if_indextoname requires.
            let ok = !unsafe { libc::if_indextoname(v6.scope_id(), name.as_mut_ptr()) }.is_null();
            let zone = if ok {
                // SAFETY: if_indextoname succeeded and NUL-terminated `name`.
                unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }
                    .to_string_lossy()
                    .into_owned()
            } else {
                v6.scope_id().to_string()
            };
            format!("{}%{zone}", v6.ip())
        }
        SocketAddr::V6(v6) => v6.ip().to_string(),
        SocketAddr::V4(v4) => v4.ip().to_string(),
    }
}

/// A sender that left mid-request: logged, as the Python receiver logs it
/// (plugin #39), and the connection closed without an answer it can't read.
fn peer_disconnected(req: &Request, reason: &str) -> Flow {
    info!("{} peer disconnected: {reason}", req.path);
    Flow::Close
}

fn set_reset_on_close(sock: &TcpStream) {
    use std::os::fd::AsRawFd;
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    // SAFETY: a valid socket fd and a correctly sized linger struct.
    unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&linger as *const libc::linger).cast(),
            std::mem::size_of::<libc::linger>() as libc::socklen_t,
        );
    }
}

struct Slot<'a>(&'a AtomicUsize);

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Take one of `max` upload slots, or `None` when all are taken. A plain
/// compare-exchange loop: `fetch_update` is deprecated in newer Rust (renamed
/// `try_update`), and `try_update` does not exist in the versions we support.
fn try_slot(counter: &AtomicUsize, max: usize) -> Option<Slot<'_>> {
    let mut n = counter.load(Ordering::SeqCst);
    while n < max {
        match counter.compare_exchange_weak(n, n + 1, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return Some(Slot(counter)),
            Err(now) => n = now,
        }
    }
    None
}

/// One upload's byte budget: a share of the download disk's current free
/// space, never eating into [`MIN_FREE_BYTES`].
#[derive(Debug, PartialEq, Eq)]
pub struct ReceiveBudget {
    pub free_bytes: u64,
    pub byte_limit: u64,
    pub percent: u64,
}

impl ReceiveBudget {
    pub fn compute(free_bytes: u64, percent: u64, min_free: u64) -> Result<Self, String> {
        let percent_bytes = (u128::from(free_bytes) * u128::from(percent) / 100) as u64;
        let byte_limit = percent_bytes.min(free_bytes.saturating_sub(min_free));
        if byte_limit == 0 {
            return Err(format!(
                "not enough free space while preserving {min_free} bytes"
            ));
        }
        Ok(ReceiveBudget {
            free_bytes,
            byte_limit,
            percent,
        })
    }

    #[allow(clippy::useless_conversion, reason = "u32 fields on 32-bit targets")]
    pub fn of(dest: &Path, percent: u64, min_free: u64) -> io::Result<Result<Self, String>> {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(dest.as_os_str().as_bytes())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let mut st = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: a valid C string and a valid out-pointer.
        if unsafe { libc::statvfs(path.as_ptr(), st.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: statvfs returned 0, so it filled `st`.
        let st = unsafe { st.assume_init() };
        let free = u64::from(st.f_bavail).saturating_mul(u64::from(st.f_frsize));
        Ok(Self::compute(free, percent, min_free))
    }
}

/// The longest URL a `links` Ask may have stored. Browsers handle a few
/// kilobytes; a longer item is skipped like a non-http one.
pub const MAX_LINK_URL_BYTES: usize = 8192;
/// What each stored link costs against the receive budget beyond its own
/// bytes: the filesystem block a small file takes.
const LINK_FILE_OVERHEAD: u64 = 4096;

/// The bytes [`store_link`] writes for `url`.
fn link_file(url: &str) -> String {
    format!("[InternetShortcut]\nURL={url}\n")
}

/// What storing `urls` costs against a [`ReceiveBudget`].
fn links_cost(urls: &[&str]) -> u64 {
    urls.iter()
        .map(|u| link_file(u).len() as u64 + LINK_FILE_OVERHEAD)
        .sum()
}

/// The URL a `links` Ask carries, stored in `dest` as an inert `.url`
/// shortcut; returns the stored name. INI form (`[InternetShortcut]`) because
/// it is plain text, needs no execute bit, and is what browsers and file
/// managers already open; a `.desktop` `Type=Link` invites the
/// executable-desktop-entry class of problem for no gain. The name comes from
/// the host and last path segment, sanitised like an uploaded file name; the
/// URL is written as a value, never interpreted, and nothing here launches
/// anything.
pub fn store_link(url: &str, dest: &Path) -> io::Result<String> {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (netloc, tail) = rest.split_at(authority_end);
    let path = tail.split(['?', '#']).next().unwrap_or_default();
    let segment = path
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or_default();
    let stem: Vec<&str> = [netloc, segment]
        .into_iter()
        .filter(|p| !p.is_empty())
        .collect();
    let mut base = safe_name(&stem.join("-"), "link");
    // Room for ".url" in a 255-byte name.
    while base.len() > archive::MAX_FILE_NAME_BYTES - 4 {
        base.pop();
    }
    let (name, mut file) = open_new(dest, &format!("{base}.url"))?;
    file.write_all(link_file(url).as_bytes())?;
    Ok(name)
}

/// The TransferID as it appears in log lines: ASCII letters, digits, `-`, `_`
/// and `.` only, at most 64 of them (a real one is a UUID), else `upload`.
/// `omdrop watch` reads `upload <tid>: stored <names>`; with no spaces or
/// colons in the tid, the first `: stored ` is always the receiver's own.
pub fn transfer_label(header: &str) -> String {
    let label: String = header
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .take(64)
        .collect();
    let label = label.trim_start_matches('.');
    if label.is_empty() {
        "upload".into()
    } else {
        label.to_string()
    }
}

/// The records naming what an upload stored, as `omdrop watch` reads them:
/// `upload TID: stored ` for none, `upload TID: stored NAME` for one, and
/// one `upload TID (K/N): stored NAME` per file, K = 1..N, in order, for
/// more. One name per record: names joined with `, ` were ambiguous, since a
/// name may hold `, ` itself, and a file named `a.png, b.txt` beside an
/// `a.png` had the watcher announce `a.png`. `(K/N)` sits where no file name
/// can, between the TID (no spaces) and the colon, and tells the watcher
/// which record completes the transfer: a `--once` window closes only after
/// the last. A record is at most a 255-byte name (log-escaped) and its
/// prefix, well under the log's cap. The Python receiver writes the same
/// records.
pub fn stored_records(tid: &str, names: &[String]) -> Vec<String> {
    let n = names.len();
    if n <= 1 {
        let name = names.first().map_or("", String::as_str);
        return vec![format!("upload {tid}: stored {name}")];
    }
    names
        .iter()
        .enumerate()
        .map(|(k, name)| format!("upload {tid} ({}/{n}): stored {name}", k + 1))
        .collect()
}

/// `str()` of a plist value, as the Python receiver's f-strings printed it.
fn py_str(value: Option<&Value>) -> String {
    match value {
        None => "None".into(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => py_value_repr(other),
    }
}

fn py_value_repr(value: &Value) -> String {
    match value {
        Value::String(s) => py_repr(s),
        Value::Integer(i) => i.to_string(),
        Value::Real(r) => r.to_string(),
        Value::Boolean(b) => if *b { "True" } else { "False" }.into(),
        Value::Data(d) => py_bytes_repr(d),
        Value::Array(items) => format!(
            "[{}]",
            items
                .iter()
                .map(py_value_repr)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Value::Dictionary(d) => format!(
            "{{{}}}",
            d.iter()
                .map(|(k, v)| format!("{}: {}", py_repr(k), py_value_repr(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        other => format!("{other:?}"),
    }
}

/// The names in a `TransferType` (a dictionary's keys, or an array's strings).
fn transfer_types(ask: &Dictionary) -> Vec<String> {
    match ask.get("TransferType") {
        Some(Value::Dictionary(d)) => d.keys().cloned().collect(),
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(Value::as_string)
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

fn detail_suffix(detail: Detail) -> String {
    if detail.is_none() {
        String::new()
    } else {
        format!(" [{detail}]")
    }
}

fn binary_plist(dict: Dictionary) -> Vec<u8> {
    let mut out = Vec::new();
    // Writing a dictionary of strings and data into a Vec cannot fail.
    let _ = Value::Dictionary(dict).to_writer_binary(&mut out);
    out
}

fn write_debug(data: &[u8], name: &str) {
    if let Err(e) = debugdump::dump(name, data, false) {
        warning!("debug dump {name} failed: {e}");
    }
}

/// `client-YYYYmmddTHHMMSSZ` for a captured certificate.
fn capture_stamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as libc::time_t;
    let mut tm = std::mem::MaybeUninit::<libc::tm>::zeroed();
    // SAFETY: valid pointers; gmtime_r fills `tm`.
    let ok = !unsafe { libc::gmtime_r(&secs, tm.as_mut_ptr()) }.is_null();
    // SAFETY: zero-initialised, filled by gmtime_r when it succeeded.
    let tm = unsafe { tm.assume_init() };
    if !ok {
        return format!("client-{secs}");
    }
    format!(
        "client-{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

/// Save what a sender presented. Research instrumentation must never be able
/// to fail a transfer: it did once, in the Python receiver, killing three real
/// iPhone connections before `/Ask` was parsed.
fn capture_peer_cert(dir: &Path, chain: &[CertificateDer<'static>]) -> io::Result<()> {
    let Some(leaf) = chain.first() else {
        warning!("peer presented NO client certificate");
        return Ok(());
    };
    let base = dir.join(capture_stamp());
    let path = base.with_extension("der");
    std::fs::write(&path, leaf.as_ref())?;
    warning!(
        "captured {}-byte client certificate -> {}",
        leaf.len(),
        path.display()
    );
    // Whether the sender supplied its issuing intermediates decides whether a
    // receiver trusting only Apple's root can build the chain at all.
    warning!("client sent a {}-certificate chain", chain.len());
    for (depth, cert) in chain.iter().enumerate() {
        std::fs::write(
            format!("{}-depth{depth}.der", base.display()),
            cert.as_ref(),
        )?;
    }
    Ok(())
}

enum Flow {
    Keep,
    Close,
}

struct Conn<'a> {
    server: &'a Server,
    id: u64,
    host: String,
    /// Ask and Upload share one TLS session, so an Upload that never passed
    /// an accepted Ask has nothing vouching for it.
    contacts_ok: bool,
    /// Set when an accepted Ask expects an Upload on this connection, and
    /// cleared when the next request's first byte arrives.
    awaiting_upload: bool,
}

impl Server {
    pub fn new(settings: Settings, tls: Arc<ServerConfig>) -> Self {
        Self::with_apple(settings, tls, Box::new(Apple))
    }

    pub fn with_apple(
        settings: Settings,
        tls: Arc<ServerConfig>,
        apple: Box<dyn AppleChecks + Send + Sync>,
    ) -> Self {
        Server {
            settings,
            tls,
            apple,
            live: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(0),
            uploads: AtomicUsize::new(0),
            links: Mutex::new(()),
        }
    }

    /// Accept forever, one thread per connection.
    pub fn serve(self: Arc<Self>, listener: TcpListener) {
        loop {
            let (sock, peer) = match listener.accept() {
                Ok(pair) => pair,
                Err(e) => {
                    // EMFILE and friends: back off rather than spin.
                    warning!("accept failed: {e}");
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
            };
            // A connection that opens and then carries no request is the
            // signature of a sender that gave up or a TLS handshake we lost,
            // invisible in the request log.
            info!("connection from [{}]:{}", host(&peer), peer.port());
            let Some(id) = self.admit(&sock, peer) else {
                continue;
            };
            let server = Arc::clone(&self);
            let spawned = std::thread::Builder::new()
                .name("connection".into())
                .spawn(move || server.connection(id, sock, peer));
            if let Err(e) = spawned {
                self.forget(id);
                error!("could not start a connection thread: {e}");
            }
        }
    }

    /// Register a new connection, or refuse it: past the per-peer cap it is
    /// refused; past the total cap the connection that has waited longest
    /// for a handshake or request head is closed to make room, and only when
    /// every connection is mid-request is the new one refused.
    fn admit(&self, sock: &TcpStream, peer: SocketAddr) -> Option<u64> {
        let limits = self.settings.limits;
        let shown = format!("[{}]:{}", host(&peer), peer.port());
        let clone = match sock.try_clone() {
            Ok(c) => c,
            Err(e) => {
                warning!("closing {shown}: {e}");
                return None;
            }
        };
        let Ok(mut live) = self.live.lock() else {
            return None;
        };
        let from_peer = live.values().filter(|l| l.ip == peer.ip()).count();
        if from_peer >= limits.max_per_peer {
            warning!(
                "{from_peer} connections already open from {}; closing {shown}",
                host(&peer)
            );
            return None;
        }
        if live.len() >= limits.max_connections {
            let oldest = live
                .iter()
                .filter_map(|(id, l)| l.waiting_since.map(|since| (since, *id)))
                .min();
            let Some((_, victim)) = oldest else {
                warning!(
                    "{} connections already open, all mid-request; closing {shown}",
                    live.len()
                );
                return None;
            };
            if let Some(old) = live.remove(&victim) {
                warning!(
                    "{} connections already open; closing the longest-waiting one, from {}, \
                     to make room for {shown}",
                    limits.max_connections,
                    old.ip
                );
                let _ = old.sock.shutdown(Shutdown::Both);
            }
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        live.insert(
            id,
            Live {
                sock: clone,
                ip: peer.ip(),
                waiting_since: Some(Instant::now()),
            },
        );
        Some(id)
    }

    fn forget(&self, id: u64) {
        if let Ok(mut live) = self.live.lock() {
            live.remove(&id);
        }
    }

    fn set_waiting(&self, id: u64, waiting: bool) {
        if let Ok(mut live) = self.live.lock()
            && let Some(entry) = live.get_mut(&id)
        {
            entry.waiting_since = waiting.then(Instant::now);
        }
    }

    /// A sender keeps its TLS session open after a transfer, and when this
    /// process stops the kernel closes that session with a FIN. An iPhone that
    /// has already left the AWDL link never acknowledges it, so the socket sat
    /// in FIN_WAIT_1 holding port 8771 for minutes and the next start could not
    /// bind (2026-09-18 03:11Z, 23 restart attempts). A reset costs nothing
    /// here: the transfer is over, and the peer is gone or about to be told.
    /// The sockets close with the process; this makes that close a reset.
    pub fn reset_sessions(&self) {
        if let Ok(mut live) = self.live.lock() {
            for (_, entry) in live.drain() {
                set_reset_on_close(&entry.sock);
            }
        }
    }

    fn connection(&self, id: u64, sock: TcpStream, peer: SocketAddr) {
        // Forgotten on the way out even if the session panics: a panic must
        // end its own connection, not hold its slot against the caps forever.
        struct Forget<'a>(&'a Server, u64);
        impl Drop for Forget<'_> {
            fn drop(&mut self) {
                self.0.forget(self.1);
            }
        }
        let _forget = Forget(self, id);
        let host = host(&peer);
        // The read side is Sock's: an idle timeout on every read, and an
        // absolute deadline for the handshake and each request head.
        let idle = self.settings.limits.idle_timeout;
        let _ = sock.set_write_timeout(Some(idle));
        self.session(id, Sock::new(sock, idle), peer, &host);
    }

    fn session(&self, id: u64, mut sock: Sock, peer: SocketAddr, host: &str) {
        let head_deadline = self.settings.limits.head_deadline;
        let mut tls = match ServerConnection::new(Arc::clone(&self.tls)) {
            Ok(t) => t,
            Err(e) => {
                error!("TLS session setup failed: {e}");
                return;
            }
        };
        // The handshake runs here, on this connection's own thread: done in
        // accept(), one sender that dropped off the link mid-handshake stopped
        // every later connection from being accepted (2026-09-30 17:13Z).
        sock.deadline = Some(Instant::now() + head_deadline);
        while tls.is_handshaking() {
            match tls.complete_io(&mut sock) {
                Ok((0, 0)) => {
                    info!(
                        "TLS handshake with [{host}]:{} failed: connection closed",
                        peer.port()
                    );
                    return;
                }
                Ok(_) => {}
                Err(e) => {
                    info!("TLS handshake with [{host}]:{} failed: {e}", peer.port());
                    return;
                }
            }
        }
        // What the handshake settled on, for interoperability evidence: the
        // protocol, the cipher suite, and whether the sender presented a
        // client certificate at all. Never the certificate itself.
        let chain = tls.peer_certificates().map_or(0, |c| c.len());
        info!(
            "TLS with [{host}]:{}: {}, {}, client certificate: {}",
            peer.port(),
            tls.protocol_version()
                .map_or_else(|| "unknown version".to_string(), |v| format!("{v:?}")),
            tls.negotiated_cipher_suite().map_or_else(
                || "unknown suite".to_string(),
                |s| format!("{:?}", s.suite())
            ),
            match chain {
                0 => "none".to_string(),
                n => format!("{n}-certificate chain"),
            }
        );
        let mut io: Io = BufReader::with_capacity(IO_CHUNK_BYTES, StreamOwned::new(tls, sock));
        let mut conn = Conn {
            server: self,
            id,
            host: host.to_string(),
            contacts_ok: false,
            awaiting_upload: false,
        };
        loop {
            // Evictable until it holds an upload slot: a /Discover or /Ask
            // body is small, and its sender can simply ask again.
            self.set_waiting(id, true);
            if conn.awaiting_upload {
                // The Upload wait covers only the gap before the next request
                // starts; a head or body that stalls gets the ordinary limits.
                // fill_buf blocks for that byte and consumes nothing.
                let wait = self.settings.limits.upload_wait;
                io.get_mut().sock.set_wait(Some(wait));
                let first = io.fill_buf().map(|b| b.is_empty());
                io.get_mut().sock.set_wait(None);
                conn.awaiting_upload = false;
                match first {
                    Ok(false) => {}
                    Ok(true) => break,
                    Err(e) => {
                        if http::is_timeout(&e) {
                            warning!(
                                "no Upload within {} s of an accepted Ask; closing the connection",
                                wait.as_secs()
                            );
                        }
                        break;
                    }
                }
            }
            io.get_mut().sock.deadline = Some(Instant::now() + head_deadline);
            let head = http::read_request(&mut io);
            io.get_mut().sock.deadline = None;
            let req = match head {
                Ok(req) => req,
                Err(HeadError::Closed) => break,
                Err(HeadError::Io(e)) => {
                    // sharingd closes the keep-alive session with a RST once a
                    // transfer is done: the normal end of a session, not a fault.
                    if http::is_timeout(&e) {
                        info!("{host} Request timed out: TimeoutError('timed out')");
                    }
                    break;
                }
                Err(HeadError::Bad {
                    status,
                    message,
                    request_line,
                }) => {
                    let _ = conn.send_error(&mut io, &request_line, status, &message);
                    break;
                }
            };
            match conn.handle(&mut io, &req) {
                Ok(Flow::Keep) => {}
                Ok(Flow::Close) | Err(_) => break,
            }
        }
        let stream = io.get_mut();
        stream.conn.send_close_notify();
        let _ = stream.flush();
        let _ = stream.sock.inner.shutdown(Shutdown::Write);
    }
}

fn has_body(req: &Request) -> bool {
    req.headers.get("Transfer-Encoding").is_some()
        || req
            .headers
            .get("Content-Length")
            .is_some_and(|v| v.trim() != "0")
}

impl Conn<'_> {
    fn settings(&self) -> &Settings {
        &self.server.settings
    }

    fn respond(
        &self,
        io: &mut Io,
        req: &Request,
        status: u16,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> io::Result<()> {
        info!("{} \"{}\" {status} -", self.host, req.request_line);
        http::write_response(io.get_mut(), status, headers, body)
    }

    fn answer(&self, io: &mut Io, req: &Request, body: &[u8]) -> io::Result<Flow> {
        let length = body.len().to_string();
        self.respond(io, req, 200, &[("Content-Length", &length)], body)?;
        Ok(if req.keep_alive() {
            Flow::Keep
        } else {
            Flow::Close
        })
    }

    fn status_only(&self, io: &mut Io, req: &Request, status: u16) -> io::Result<Flow> {
        self.respond(io, req, status, &[("Content-Length", "0")], b"")?;
        Ok(if req.keep_alive() {
            Flow::Keep
        } else {
            Flow::Close
        })
    }

    fn reject(&self, io: &mut Io, req: &Request, status: u16, reason: &str) -> io::Result<Flow> {
        warning!("{} rejected: {reason}", req.path);
        self.respond(
            io,
            req,
            status,
            &[("Content-Length", "0"), ("Connection", "close")],
            b"",
        )?;
        Ok(Flow::Close)
    }

    /// Read what the sender still has in flight before closing, after an
    /// upload answered without its closing chunk (plugin #47). A Mac's
    /// sharingd sends that chunk only once it has the answer; closing with it
    /// unread, or still on the way, makes the kernel send a TCP RST, and a Mac
    /// that sees the reset reports the stored transfer as failed (sharingd:
    /// unexpected-NSPOSIXErrorDomain-54). An iPhone instead keeps the
    /// connection open and waits for us to close. So read until the sender
    /// closes or goes quiet for `drain_quiet`, never longer than `drain_limit`
    /// in all. What is read is discarded, never parsed or stored.
    fn drain_before_close(&self, io: &mut Io) {
        let limits = self.settings().limits;
        if io.get_mut().flush().is_err() {
            return;
        }
        let end = Instant::now() + limits.drain_limit;
        let mut buf = vec![0u8; IO_CHUNK_BYTES];
        loop {
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            io.get_mut()
                .sock
                .set_wait(Some(limits.drain_quiet.min(left)));
            match io.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        io.get_mut().sock.set_wait(None);
    }

    fn send_error(
        &self,
        io: &mut Io,
        request_line: &str,
        status: u16,
        message: &str,
    ) -> io::Result<()> {
        info!("{} code {status}, message {message}", self.host);
        info!("{} \"{request_line}\" {status} -", self.host);
        http::write_response(
            io.get_mut(),
            status,
            &[("Connection", "close"), ("Content-Length", "0")],
            b"",
        )
    }

    fn visibility(&self) -> Visibility {
        contacts::visibility(&self.settings().visibility_path)
    }

    fn handle(&mut self, io: &mut Io, req: &Request) -> io::Result<Flow> {
        // Acknowledge `Expect: 100-continue` up front, except for an upload,
        // whose framing and disk-relative limit are validated first.
        let expect = req
            .headers
            .get("Expect")
            .is_some_and(|v| v.eq_ignore_ascii_case("100-continue"));
        if expect && req.minor >= 1 && req.path != "/Upload" {
            http::write_response(io.get_mut(), 100, &[], b"")?;
        }
        let flow = match req.method.as_str() {
            "POST" => self.post(io, req)?,
            "GET" => self.answer(io, req, b"\n")?,
            "HEAD" => {
                self.respond(io, req, 200, &[("Content-type", "text/html")], b"")?;
                if req.keep_alive() {
                    Flow::Keep
                } else {
                    Flow::Close
                }
            }
            other => {
                self.send_error(
                    io,
                    &req.request_line,
                    501,
                    &format!("Unsupported method ({})", py_repr(other)),
                )?;
                Flow::Close
            }
        };
        // A GET or HEAD body is never read; whatever follows it is not a
        // request, so the connection ends here.
        if req.method != "POST" && has_body(req) {
            return Ok(Flow::Close);
        }
        Ok(flow)
    }

    fn post(&mut self, io: &mut Io, req: &Request) -> io::Result<Flow> {
        debug!("POST {}, headers: {}", req.path, req.headers);
        if let Some(dir) = &self.settings().peercert_dir {
            let chain = tls::peer_chain(&io.get_ref().conn);
            if let Err(e) = capture_peer_cert(dir, &chain) {
                error!("peer certificate capture failed; continuing: {e}");
            }
        }
        if req.path == "/Upload" {
            return self.upload(io, req);
        }
        if req.path != "/Discover" && req.path != "/Ask" {
            // The body is not read, so nothing after it can be a request.
            let close = has_body(req);
            let headers: &[(&str, &str)] = if close {
                &[("Content-Length", "0"), ("Connection", "close")]
            } else {
                &[("Content-Length", "0")]
            };
            self.respond(io, req, 400, headers, b"")?;
            return Ok(if close || !req.keep_alive() {
                Flow::Close
            } else {
                Flow::Keep
            });
        }
        let body = match http::read_small_body(io, &req.headers, MAX_METADATA_BYTES) {
            Ok(body) => body,
            Err(BodyError::Timeout(_)) => {
                return self.reject(io, req, 408, "request body read timed out");
            }
            Err(BodyError::ConnectionLost(m)) => return Ok(peer_disconnected(req, &m)),
            Err(e) => return self.reject(io, req, e.status(), &e.to_string()),
        };
        debug!("buffered bounded {}-byte body for {}", body.len(), req.path);
        if req.path == "/Discover" {
            self.discover(io, req, &body)
        } else {
            self.ask(io, req, &body)
        }
    }

    /// Contacts Only should mean a stranger does not see this machine at all,
    /// as Apple's mode does. Before this an unknown Mac got a full answer,
    /// tiled us in its share sheet, and was turned away at /Ask (measured
    /// 2026-09-20, 403 in 23 ms): presence leaked.
    ///
    /// This hides us from an HONEST stranger and nothing more: /Discover
    /// carries SenderRecordData but no client certificate, so a replay of a
    /// contact's record is still answered. Acceptable for who sees a tile,
    /// NEVER for who may send, which is why the /Ask gate does the full
    /// certificate-bound check. Silence (401) rather than 403: a refusal
    /// would tell the stranger the machine is there.
    fn discover(&mut self, io: &mut Io, req: &Request, body: &[u8]) -> io::Result<Flow> {
        if self.visibility() == Visibility::Contacts {
            let record = safeplist::parse_dict(body).and_then(|d| {
                d.get("SenderRecordData")
                    .and_then(Value::as_data)
                    .map(<[u8]>::to_vec)
            });
            let known = contacts::known_hashes(&self.settings().known_senders_path);
            let (outcome, detail) =
                contacts::decide_discovery(record.as_deref(), &known, &*self.server.apple);
            if outcome != Outcome::Accept {
                info!(
                    "discovery withheld (contacts only): {}{}",
                    outcome.why(),
                    detail_suffix(detail)
                );
                return self.status_only(io, req, 401);
            }
        }
        write_debug(body, "receive_discover_request.plist");
        let s = self.settings();
        let mut answer = Dictionary::new();
        answer.insert("ReceiverComputerName".into(), Value::String(s.name.clone()));
        answer.insert(
            "ReceiverMediaCapabilities".into(),
            Value::Data(MEDIA_CAPABILITIES.to_vec()),
        );
        answer.insert("ReceiverModelName".into(), Value::String(s.model.clone()));
        answer.insert("IsAirDropable".into(), Value::Boolean(true));
        // The Apple ID validation record is what lets a Contacts Only sender
        // recognise us.
        if let Some(record) = &s.record {
            answer.insert("ReceiverRecordData".into(), Value::Data(record.clone()));
        }
        let resp = binary_plist(answer);
        write_debug(&resp, "receive_discover_response.plist");
        self.answer(io, req, &resp)
    }

    /// 2026-09-12, iPhone on iOS 26, two link transfers: /Discover 200, /Ask
    /// 200 for a 108-byte `x-com.webloc`, then NO /Upload while the phone said
    /// "Sent". The Ask had been answered with the two name keys only; a Mac's
    /// Discover answer also carries ReceiverMediaCapabilities, which is how a
    /// sender learns what the receiver takes. So the Ask is answered with the
    /// same three keys, and what was asked for is logged: that line separates
    /// "the sender never uploaded" from "the upload failed on our side".
    fn ask(&mut self, io: &mut Io, req: &Request, body: &[u8]) -> io::Result<Flow> {
        write_debug(body, "receive_ask_request.plist");
        let ask = match safeplist::parse(body) {
            Ok(Value::Dictionary(d)) => d,
            Ok(_) => Dictionary::new(),
            Err(e) => {
                error!("ask: undecodable {}-byte body: {e}", body.len());
                Dictionary::new()
            }
        };
        let empty = Vec::new();
        let files = ask.get("Files").and_then(Value::as_array).unwrap_or(&empty);
        let items = ask.get("Items").and_then(Value::as_array).unwrap_or(&empty);
        let types = transfer_types(&ask);
        // Before anything is built from them: the log line below grows with
        // the item count.
        if items.len() > MAX_ARCHIVE_MEMBERS {
            return self.reject(
                io,
                req,
                413,
                &format!("Ask exceeds {MAX_ARCHIVE_MEMBERS}-item limit"),
            );
        }
        let listing: Vec<String> = files
            .iter()
            .take(MAX_ARCHIVE_MEMBERS)
            .map(|f| {
                let f = f.as_dictionary();
                let get = |k: &str| py_str(f.and_then(|d| d.get(k)));
                format!(
                    "{} {} {}B",
                    get("FileName"),
                    get("FileType"),
                    get("FileSize")
                )
            })
            .collect();
        let listing = if !listing.is_empty() {
            listing.join("; ")
        } else if !items.is_empty() {
            py_value_repr(&Value::Array(items.clone()))
        } else {
            "-".into()
        };
        info!(
            "ask from {} ({}): type {}, {} item(s): {listing}",
            py_str(ask.get("SenderComputerName")),
            py_str(ask.get("SenderModelName")),
            if types.is_empty() {
                "?".into()
            } else {
                types.join(",")
            },
            files.len(),
        );
        // Contacts Only is enforced here, for two reasons measured 2026-09-18:
        // a sender presents its Apple-issued certificate on /Ask and never on
        // /Discover, and /Ask is when a transfer is actually proposed, so a
        // refusal costs the sender a clear error, not a disappearance.
        if self.visibility() == Visibility::Contacts {
            let chain = tls::peer_chain(&io.get_ref().conn);
            let record = ask.get("SenderRecordData").and_then(Value::as_data);
            let known = contacts::known_hashes(&self.settings().known_senders_path);
            let leaf = chain.first().map(|c| c.as_ref());
            let (outcome, detail) = contacts::decide(record, leaf, &known, &*self.server.apple);
            if outcome != Outcome::Accept {
                // No identifier is logged: the record's hashes are reversible
                // to a phone number by brute force.
                warning!(
                    "ask REFUSED (contacts only): {}{}",
                    outcome.why(),
                    detail_suffix(detail)
                );
                return self.status_only(io, req, 403);
            }
            info!("ask accepted: {}", outcome.why());
            self.contacts_ok = true;
        }
        // A `links` transfer is Ask-only: with SUPPORTS_URL advertised, iOS
        // puts the URL in Items and sends no /Upload, so accepting the Ask IS
        // the transfer. Store it, or the link is lost. NEVER open it: in
        // Everyone mode any device in range could make this machine visit an
        // arbitrary URL. A file the user clicks is all we offer.
        if types.iter().any(|t| t == "links") {
            let mut urls: Vec<&str> = Vec::new();
            for item in items {
                let url = match item.as_string() {
                    Some(u) if u.starts_with("http://") || u.starts_with("https://") => u,
                    _ => {
                        let shown = py_value_repr(item);
                        warning!(
                            "ask: ignoring non-http item {}",
                            shown.chars().take(80).collect::<String>()
                        );
                        continue;
                    }
                };
                // A line break would end the shortcut's URL= line early and
                // start another, and whitespace would make the `link stored
                // as NAME -> URL` log line ambiguous to `omdrop watch`: such
                // a URL is malformed (a real one is percent-encoded), not a
                // link.
                if url.chars().any(|c| c.is_control() || c.is_whitespace()) {
                    let shown = py_repr(url);
                    warning!(
                        "ask: ignoring item with control characters or spaces {}",
                        shown.chars().take(80).collect::<String>()
                    );
                    continue;
                }
                if url.len() > MAX_LINK_URL_BYTES {
                    let shown = py_repr(url);
                    warning!(
                        "ask: ignoring item longer than {MAX_LINK_URL_BYTES} bytes {}",
                        shown.chars().take(80).collect::<String>()
                    );
                    continue;
                }
                urls.push(url);
            }
            // The links are the whole transfer, so they get the budget an
            // upload would: nothing is stored unless all of them fit. The
            // check and the writes are one step across connections: two
            // Asks checked against the same free bytes could together write
            // past MIN_FREE_BYTES. Writing a few small files is quick.
            let _reserving = (!urls.is_empty())
                .then(|| self.server.links.lock().unwrap_or_else(|e| e.into_inner()));
            if !urls.is_empty() {
                let s = self.settings();
                let cost = links_cost(&urls);
                match ReceiveBudget::of(&s.dest, s.max_receive_percent, s.min_free_bytes) {
                    Ok(Ok(b)) if cost <= b.byte_limit => {}
                    Ok(Ok(b)) => {
                        let reason = format!(
                            "links need {cost} bytes; {}% of {} free bytes allows {}",
                            b.percent, b.free_bytes, b.byte_limit
                        );
                        return self.reject(io, req, 507, &reason);
                    }
                    Ok(Err(e)) => return self.reject(io, req, 507, &e),
                    Err(e) => return self.reject(io, req, 507, &format!("storage failed: {e}")),
                }
            }
            for url in urls {
                match store_link(url, &self.settings().dest) {
                    Ok(stored) => info!("link stored as {stored} -> {url}"),
                    // Answering 200 would tell the sender a lost link arrived.
                    Err(e) => return self.reject(io, req, 507, &format!("storage failed: {e}")),
                }
            }
        }
        let s = self.settings();
        let mut answer = Dictionary::new();
        answer.insert("ReceiverComputerName".into(), Value::String(s.name.clone()));
        answer.insert(
            "ReceiverMediaCapabilities".into(),
            Value::Data(MEDIA_CAPABILITIES.to_vec()),
        );
        answer.insert("ReceiverModelName".into(), Value::String(s.model.clone()));
        answer.insert("IsAirDropable".into(), Value::Boolean(true));
        let resp = binary_plist(answer);
        write_debug(&resp, "receive_ask_response.plist");
        let flow = self.answer(io, req, &resp)?;
        // A links Ask is the whole transfer; every other kind is followed by
        // an Upload on this connection.
        if !types.iter().any(|t| t == "links") {
            self.awaiting_upload = true;
        }
        Ok(flow)
    }

    fn upload(&mut self, io: &mut Io, req: &Request) -> io::Result<Flow> {
        // The Upload itself carries no validation record to judge.
        if self.visibility() == Visibility::Contacts && !self.contacts_ok {
            return self.reject(io, req, 403, "contacts-only upload has no accepted Ask");
        }
        let ctype = req.headers.get("Content-Type").unwrap_or_default();
        let ctype = ctype
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_lowercase();
        if ctype != "application/x-dvzip" && ctype != "application/x-cpio" {
            return self.reject(
                io,
                req,
                415,
                &format!("unsupported Content-Type {}", py_repr(&ctype)),
            );
        }
        let Some(slot) = try_slot(&self.server.uploads, MAX_CONCURRENT_UPLOADS) else {
            return self.reject(io, req, 503, "too many uploads in progress");
        };
        self.server.set_waiting(self.id, false);
        let s = self.settings();
        let tid = transfer_label(req.headers.get("TransferID").unwrap_or_default());
        let budget = match ReceiveBudget::of(&s.dest, s.max_receive_percent, s.min_free_bytes) {
            Ok(Ok(b)) => b,
            Ok(Err(e)) => return self.reject(io, req, 413, &e),
            Err(e) => return self.reject(io, req, 507, &format!("storage failed: {e}")),
        };
        let plan = match http::body_plan(&req.headers, budget.byte_limit) {
            Ok(plan) => plan,
            Err(e) => return self.reject(io, req, e.status(), &e.to_string()),
        };
        info!(
            "upload {tid}: {}% of {} free bytes allows {} bytes",
            budget.percent, budget.free_bytes, budget.byte_limit
        );
        if req
            .headers
            .get("Expect")
            .is_some_and(|v| v.eq_ignore_ascii_case("100-continue"))
        {
            http::write_response(io.get_mut(), 100, &[], b"")?;
        }
        let mut deadline = ReadDeadline::new();
        let limits = ExtractLimits {
            byte_limit: budget.byte_limit,
            max_members: MAX_ARCHIVE_MEMBERS,
            min_free_bytes: s.min_free_bytes,
        };
        let progress = ExtractProgress::new();
        let step = s.limits.upload_step;
        let wait_cell = Arc::clone(&io.get_mut().sock.wait);
        let set_upload_wait = |w: Option<Duration>| set_wait(&wait_cell, w);
        let archive_whole = || progress.whole();
        let mut body =
            BodyReader::new(io, plan, budget.byte_limit, &mut deadline).with_patience(Patience {
                step,
                limit: s.limits.idle_timeout,
                set_wait: &set_upload_wait,
                is_complete: &archive_whole,
            });
        let result = archive::extract(&mut body, &s.dest, &limits, &PARTIALS, &progress);
        // The Python receiver read the whole body before decoding it, so the
        // sender always got to read its answer. A stream decoded as it arrives
        // fails early; read the rest (still bounded) so the answer is not lost
        // to a reset.
        if matches!(
            result,
            Err(ArchiveError::Limit(_) | ArchiveError::Invalid(_))
        ) {
            let _ = io::copy(&mut body, &mut io::sink());
        }
        let wire = body.total();
        let failure = match result {
            Ok(done) => {
                if done.unterminated {
                    warning!(
                        "upload {tid}: no closing chunk after {} s, but the archive is complete; storing it",
                        step.as_secs()
                    );
                }
                info!(
                    "upload {tid}: {wire} bytes dvzip (TotalBytes {})",
                    req.headers.get("TotalBytes").unwrap_or("None")
                );
                info!(
                    "upload {tid}: decoded to {} bytes, magic {}",
                    done.decoded_bytes,
                    py_bytes_repr(&done.magic)
                );
                for record in stored_records(&tid, &done.names) {
                    info!("{record}");
                }
                // A finished transfer ends its connection (plugin #69): an
                // iPhone stays on "Sending" while the connection is open, so
                // keeping it alive held the sender's UI for the 30 s idle
                // limit. A sender wanting another request opens a new one.
                let close = [("Content-Length", "0"), ("Connection", "close")];
                if !done.unterminated {
                    self.respond(io, req, 200, &close, b"")?;
                    return Ok(Flow::Close);
                }
                // The closing chunk never came, so this connection's framing
                // is unknown: answer, then drain what is still in flight
                // before closing. The upload slot is not held through the
                // drain.
                drop(slot);
                self.respond(io, req, 200, &close, b"")?;
                self.drain_before_close(io);
                return Ok(Flow::Close);
            }
            Err(e) => e,
        };
        match failure {
            ArchiveError::Limit(m) => self.reject(io, req, 413, &m),
            ArchiveError::Invalid(m) => self.reject(
                io,
                req,
                422,
                &format!("upload is not a valid bounded DVZip archive: {m}"),
            ),
            ArchiveError::Io(e) => match BodyError::classify(e) {
                Ok(BodyError::Timeout(stall)) => {
                    // Chunked framing announces no length, so there is none to name.
                    let report = deadline.stall_report(stall, plan.expected());
                    // Which side stopped: with every file decoded and the
                    // compressed stream ended, only the request's end was
                    // missing; past the trailer but not at the stream's end,
                    // the body is cut short; before the trailer, file data was.
                    let phase = if progress.whole() {
                        "after the archive's end: every file arrived, the request never ended"
                    } else if progress.trailer_seen() {
                        "after the archive's trailer, inside its compressed stream: a gzip footer or DVZip block is cut short"
                    } else {
                        "inside the archive: file data still missing"
                    };
                    let total = req.headers.get("TotalBytes").unwrap_or("None");
                    self.reject(
                        io,
                        req,
                        408,
                        &format!(
                            "upload {tid}: {report}; {wire} payload bytes, decoded {} of TotalBytes {total}; stalled {phase}",
                            progress.decoded()
                        ),
                    )
                }
                // The sender left mid-upload: no answer can reach it, and it is
                // not a storage failure. The partial files and the upload slot
                // were released when extract and the slot guard returned.
                Ok(BodyError::ConnectionLost(m)) => Ok(peer_disconnected(
                    req,
                    &format!(
                        "upload {tid}: {m}; {} HTTP body/framing bytes read in {:.1} s",
                        deadline.transferred(),
                        deadline.elapsed().as_secs_f64()
                    ),
                )),
                Ok(e) => self.reject(io, req, e.status(), &e.to_string()),
                Err(e) => self.reject(io, req, 507, &format!("storage failed: {e}")),
            },
        }
    }
}

#[cfg(test)]
mod tests;
