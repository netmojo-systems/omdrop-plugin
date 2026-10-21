//! The receiver's HTTP/1.1: request heads, bounded bodies, responses.
//!
//! sharingd sends `/Discover` and `/Ask` with `Transfer-Encoding: chunked` and
//! no Content-Length, and `/Upload` chunked too, so every body goes through
//! one bounded reader ([`BodyReader`]), never a trusted Content-Length. Framing
//! is validated ([`body_plan`]) before `100 Continue` is sent or any body byte
//! is read. Two clocks guard each body: the socket's idle timeout (nothing
//! arrived for [`READ_IDLE_TIMEOUT`]) and a [`ReadDeadline`] that requires
//! sustained progress, so a peer that trickles bytes cannot hold a thread
//! forever.

use std::fmt;
use std::io::{self, BufRead, Read, Write};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::archive::{IO_CHUNK_BYTES, py_bytes_repr, py_repr};

/// Applies to the TLS handshake, request heads and every body read.
pub const READ_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Grace before the minimum read rate applies.
pub const INITIAL_READ_SECONDS: f64 = 60.0;
/// A body must average at least this after the grace period.
pub const MIN_READ_BYTES_PER_SECOND: u64 = 64 * 1024;
/// `/Discover` and `/Ask` bodies.
pub const MAX_METADATA_BYTES: u64 = 1024 * 1024;
pub const MAX_CHUNK_LINE_BYTES: usize = 128;
pub const MAX_TRAILER_BYTES: usize = 8 * 1024;
/// Python's `http.server` limits: one request or header line, and headers.
pub const MAX_LINE_BYTES: usize = 65536;
pub const MAX_HEADERS: usize = 100;

/// Which clock a stalled body ran out of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stall {
    /// Nothing arrived for [`READ_IDLE_TIMEOUT`].
    Idle,
    /// Arriving, but slower than [`MIN_READ_BYTES_PER_SECOND`].
    Rate,
}

/// Why a request body was refused.
#[derive(Debug)]
pub enum BodyError {
    /// Malformed framing (400).
    Invalid(String),
    /// Over the byte limit (413).
    TooLarge(String),
    /// The body stalled (408).
    Timeout(Stall),
    /// Not a refusal: a chunked body went quiet at a chunk boundary when
    /// what had arrived was already a whole archive (see [`Patience`]). The
    /// extractor treats it as the body's end; it never reaches a sender.
    Complete,
    /// Not a refusal either: the connection failed mid-body (reset, aborted,
    /// or a TLS session that ended without close_notify), so the sender has
    /// gone and nothing can be answered (plugin #90).
    ConnectionLost(String),
}

impl BodyError {
    pub fn status(&self) -> u16 {
        match self {
            // ConnectionLost is never answered; 400 only keeps this total.
            BodyError::Invalid(_) | BodyError::ConnectionLost(_) => 400,
            BodyError::TooLarge(_) => 413,
            BodyError::Timeout(_) | BodyError::Complete => 408,
        }
    }

    fn into_io(self) -> io::Error {
        io::Error::other(self)
    }

    /// What an I/O error from a body read means: a `BodyError` raised inside a
    /// reader (including [`BodyError::ConnectionLost`]), a socket timeout
    /// ([`Stall::Idle`]), or neither (`Err`: the disk failed).
    pub fn classify(e: io::Error) -> Result<BodyError, io::Error> {
        if e.get_ref().is_some_and(|inner| inner.is::<BodyError>()) {
            return match e.into_inner().map(|inner| inner.downcast::<BodyError>()) {
                Some(Ok(inner)) => Ok(*inner),
                _ => Err(io::Error::other("internal error unwrapping a body error")),
            };
        }
        if is_timeout(&e) {
            return Ok(BodyError::Timeout(Stall::Idle));
        }
        Err(e)
    }
}

impl fmt::Display for BodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BodyError::Invalid(m) | BodyError::TooLarge(m) | BodyError::ConnectionLost(m) => {
                f.write_str(m)
            }
            BodyError::Timeout(Stall::Idle) => f.write_str("timed out"),
            BodyError::Timeout(Stall::Rate) => {
                f.write_str("request body did not meet minimum read rate")
            }
            BodyError::Complete => f.write_str("the body went quiet after a complete archive"),
        }
    }
}

impl std::error::Error for BodyError {}

/// A socket read that hit `SO_RCVTIMEO`.
pub fn is_timeout(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// Whether an I/O error from a body read is [`BodyError::Complete`].
pub fn is_complete(e: &io::Error) -> bool {
    e.get_ref()
        .and_then(|inner| inner.downcast_ref::<BodyError>())
        .is_some_and(|b| matches!(b, BodyError::Complete))
}

/// How a chunked upload waits at a chunk boundary (plugin #41, 2026-10-12).
///
/// An iPhone sometimes delivers every byte of an `/Upload` and then never
/// sends the chunked body's closing `0` chunk: its progress bar sits full,
/// and the upload used to die on the idle timeout. So the wait for the next
/// chunk-size line runs in `step`s without consuming anything. After each
/// quiet step it asks `is_complete`, and when what arrived is already a
/// whole archive the body ends there ([`BodyError::Complete`]). Otherwise it
/// waits on, up to `limit` of silence as before. Only a chunk boundary is
/// checked, where the missing closing chunk would be: a pause mid-chunk is
/// never taken for the end.
pub struct Patience<'p> {
    pub step: Duration,
    pub limit: Duration,
    /// Shortens each socket read to the step (`Some`), or restores it (`None`).
    pub set_wait: &'p dyn Fn(Option<Duration>),
    pub is_complete: &'p dyn Fn() -> bool,
}

/// Requires sustained progress as well as an idle-socket timeout:
/// [`INITIAL_READ_SECONDS`] plus one second per [`MIN_READ_BYTES_PER_SECOND`]
/// bytes received.
#[derive(Debug)]
pub struct ReadDeadline {
    started: Instant,
    transferred: u64,
}

impl Default for ReadDeadline {
    fn default() -> Self {
        Self::new()
    }
}

impl ReadDeadline {
    pub fn new() -> Self {
        Self::started_at(Instant::now())
    }

    pub fn started_at(started: Instant) -> Self {
        ReadDeadline {
            started,
            transferred: 0,
        }
    }

    pub fn transferred(&self) -> u64 {
        self.transferred
    }

    /// How long the body has been read for.
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    /// Count `size` received bytes; a [`Stall::Rate`] timeout when the body is
    /// behind the minimum rate.
    pub fn note(&mut self, size: usize) -> Result<(), BodyError> {
        self.transferred += size as u64;
        let allowed =
            INITIAL_READ_SECONDS + self.transferred as f64 / MIN_READ_BYTES_PER_SECOND as f64;
        if self.started.elapsed().as_secs_f64() > allowed {
            return Err(BodyError::Timeout(Stall::Rate));
        }
        Ok(())
    }

    /// How far a timed-out body got, so a stall reads plainly in the log. A
    /// stopped transfer and a slow one call for different fixes: a radio that
    /// stopped carrying the upload is not helped by a longer timeout, and the
    /// byte count and elapsed time tell them apart.
    pub fn stall_report(&self, stall: Stall, expected: Option<u64>) -> String {
        let why = match stall {
            Stall::Rate => format!("slower than {MIN_READ_BYTES_PER_SECOND} bytes/s"),
            Stall::Idle => format!("nothing arrived for {} s", READ_IDLE_TIMEOUT.as_secs()),
        };
        let of = expected.map(|n| format!(" of {n}")).unwrap_or_default();
        format!(
            "request body read timed out, {why}: {}{of} bytes in {:.1} s",
            self.transferred,
            self.started.elapsed().as_secs_f64()
        )
    }
}

/// Request headers, in order; names compared case-insensitively. Values are
/// decoded as ISO-8859-1, as Python's `http.server` does.
#[derive(Clone, Debug, Default)]
pub struct Headers(pub Vec<(String, String)>);

impl Headers {
    /// The first value of `name`.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn count(&self, name: &str) -> usize {
        self.0
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .count()
    }
}

impl fmt::Display for Headers {
    /// `Name: value; Name: value`, on one line: a log line must never be
    /// split by text a peer sent.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, (k, v)) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str("; ")?;
            }
            write!(f, "{k}: {v}")?;
        }
        Ok(())
    }
}

/// How a request body is framed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyPlan {
    Chunked,
    Length(u64),
}

impl BodyPlan {
    /// The announced length, for the stall report.
    pub fn expected(self) -> Option<u64> {
        match self {
            BodyPlan::Chunked => None,
            BodyPlan::Length(n) => Some(n),
        }
    }
}

/// Validate framing before sending 100 Continue or reading any body. Chunked
/// wins over Content-Length; anything but plain `chunked` is refused, and so
/// are repeated framing headers (a request-smuggling shape Python's server
/// resolved by taking the first).
pub fn body_plan(headers: &Headers, limit: u64) -> Result<BodyPlan, BodyError> {
    for name in ["Transfer-Encoding", "Content-Length"] {
        if headers.count(name) > 1 {
            return Err(BodyError::Invalid(format!("repeated {name} header")));
        }
    }
    let transfer = headers.get("Transfer-Encoding").unwrap_or_default();
    if !transfer.is_empty() {
        let encodings: Vec<String> = transfer
            .split(',')
            .map(|p| p.trim().to_ascii_lowercase())
            .collect();
        if encodings != ["chunked"] {
            return Err(BodyError::Invalid(format!(
                "unsupported Transfer-Encoding: {}",
                py_repr(transfer)
            )));
        }
        return Ok(BodyPlan::Chunked);
    }
    let Some(value) = headers.get("Content-Length") else {
        return Err(BodyError::Invalid(
            "request body needs Content-Length or chunked encoding".into(),
        ));
    };
    let digits = value.trim();
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(BodyError::Invalid(format!(
            "invalid Content-Length: {}",
            py_repr(value)
        )));
    }
    let too_large = || BodyError::TooLarge(format!("request body exceeds {limit}-byte limit"));
    let length = digits.parse::<u64>().map_err(|_| too_large())?;
    if length > limit {
        return Err(too_large());
    }
    Ok(BodyPlan::Length(length))
}

/// Read one line of at most `max` bytes (stopping after `\n`), as Python's
/// `readline(max)`.
pub fn read_line(r: &mut impl BufRead, max: usize) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    while line.len() < max {
        let available = match r.fill_buf() {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if available.is_empty() {
            break;
        }
        let room = max - line.len();
        let window = available
            .get(..available.len().min(room))
            .unwrap_or_default();
        match window.iter().position(|&b| b == b'\n') {
            Some(i) => {
                line.extend_from_slice(window.get(..=i).unwrap_or_default());
                r.consume(i + 1);
                return Ok(line);
            }
            None => {
                let n = window.len();
                line.extend_from_slice(window);
                r.consume(n);
            }
        }
    }
    Ok(line)
}

enum Chunk {
    Size,
    Data(u64),
    End,
    Done,
}

/// Streams one framed request body under a byte limit and a [`ReadDeadline`].
/// Its errors are `io::Error`s wrapping a [`BodyError`], or a socket timeout;
/// pass them to [`BodyError::classify`].
pub struct BodyReader<'a, R: BufRead> {
    r: &'a mut R,
    limit: u64,
    total: u64,
    deadline: &'a mut ReadDeadline,
    length_left: u64,
    chunk: Option<Chunk>,
    patience: Option<Patience<'a>>,
}

impl<'a, R: BufRead> BodyReader<'a, R> {
    pub fn new(r: &'a mut R, plan: BodyPlan, limit: u64, deadline: &'a mut ReadDeadline) -> Self {
        let (length_left, chunk) = match plan {
            BodyPlan::Length(n) => (n, None),
            BodyPlan::Chunked => (0, Some(Chunk::Size)),
        };
        BodyReader {
            r,
            limit,
            total: 0,
            deadline,
            length_left,
            chunk,
            patience: None,
        }
    }

    /// Wait at chunk boundaries as [`Patience`] describes. Chunked bodies only.
    pub fn with_patience(mut self, patience: Patience<'a>) -> Self {
        self.patience = Some(patience);
        self
    }

    /// Body bytes delivered so far (framing excluded).
    pub fn total(&self) -> u64 {
        self.total
    }

    fn line(&mut self) -> io::Result<Vec<u8>> {
        let line = read_line(self.r, MAX_CHUNK_LINE_BYTES + 1)?;
        self.deadline.note(line.len()).map_err(BodyError::into_io)?;
        Ok(line)
    }

    /// Wait for the next chunk-size line's first byte without consuming it,
    /// in [`Patience::step`]s, asking after each quiet step whether the
    /// archive is already whole. `fill_buf` takes nothing from the stream, so
    /// a step that times out loses no byte; once one is there, the line is
    /// read at the normal idle timeout.
    fn await_boundary(&mut self) -> io::Result<()> {
        let Some(p) = &self.patience else {
            return Ok(());
        };
        (p.set_wait)(Some(p.step));
        let mut idle = Duration::ZERO;
        let waited = loop {
            match self.r.fill_buf() {
                Ok(_) => break Ok(()),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if is_timeout(&e) => {
                    idle += p.step;
                    if (p.is_complete)() {
                        break Err(BodyError::Complete.into_io());
                    }
                    if idle >= p.limit {
                        break Err(e);
                    }
                }
                Err(e) => break Err(e),
            }
        };
        (p.set_wait)(None);
        waited
    }

    fn data(&mut self, buf: &mut [u8], left: u64, truncated: &str) -> io::Result<usize> {
        let want = buf
            .len()
            .min(IO_CHUNK_BYTES)
            .min(usize::try_from(left).unwrap_or(usize::MAX));
        let n = loop {
            match self.r.read(&mut buf[..want]) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                other => break other?,
            }
        };
        if n == 0 {
            return Err(BodyError::Invalid(truncated.into()).into_io());
        }
        self.deadline.note(n).map_err(BodyError::into_io)?;
        self.total += n as u64;
        Ok(n)
    }

    fn chunked(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.chunk.take() {
                None | Some(Chunk::Done) => {
                    self.chunk = Some(Chunk::Done);
                    return Ok(0);
                }
                Some(Chunk::Size) => {
                    if let Err(e) = self.await_boundary() {
                        self.chunk = Some(Chunk::Size);
                        return Err(e);
                    }
                    let line = self.line()?;
                    if line.is_empty()
                        || line.len() > MAX_CHUNK_LINE_BYTES
                        || line.last() != Some(&b'\n')
                    {
                        return Err(BodyError::Invalid(
                            "invalid or overlong chunk-size line".into(),
                        )
                        .into_io());
                    }
                    let token = line
                        .split(|&b| b == b';')
                        .next()
                        .unwrap_or_default()
                        .trim_ascii();
                    let bad = || {
                        let shown = token.get(..token.len().min(40)).unwrap_or_default();
                        BodyError::Invalid(format!("invalid chunk size: {}", py_bytes_repr(shown)))
                            .into_io()
                    };
                    if token.is_empty() || !token.iter().all(u8::is_ascii_hexdigit) {
                        return Err(bad());
                    }
                    let too_large = || {
                        BodyError::TooLarge(format!(
                            "request body exceeds {}-byte limit",
                            self.limit
                        ))
                        .into_io()
                    };
                    let size = std::str::from_utf8(token)
                        .ok()
                        .and_then(|t| u64::from_str_radix(t, 16).ok())
                        .ok_or_else(too_large)?;
                    if size == 0 {
                        let mut trailers = 0;
                        loop {
                            let line = self.line()?;
                            trailers += line.len();
                            if line.is_empty()
                                || line.len() > MAX_CHUNK_LINE_BYTES
                                || trailers > MAX_TRAILER_BYTES
                            {
                                return Err(BodyError::Invalid(
                                    "invalid or overlong chunk trailers".into(),
                                )
                                .into_io());
                            }
                            if line == b"\r\n" || line == b"\n" {
                                break;
                            }
                        }
                        self.chunk = Some(Chunk::Done);
                        return Ok(0);
                    }
                    if size > self.limit - self.total {
                        return Err(too_large());
                    }
                    self.chunk = Some(Chunk::Data(size));
                }
                Some(Chunk::Data(left)) => {
                    let n = self.data(buf, left, "truncated chunk data")?;
                    let left = left - n as u64;
                    self.chunk = Some(if left == 0 {
                        Chunk::End
                    } else {
                        Chunk::Data(left)
                    });
                    return Ok(n);
                }
                Some(Chunk::End) => {
                    let mut ending = [0u8; 2];
                    let n = crate::archive::read_full(self.r, &mut ending)?;
                    self.deadline.note(n).map_err(BodyError::into_io)?;
                    if n != 2 || ending != *b"\r\n" {
                        return Err(BodyError::Invalid("chunk data missing CRLF".into()).into_io());
                    }
                    self.chunk = Some(Chunk::Size);
                }
            }
        }
    }
}

impl<R: BufRead> Read for BodyReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_framed(buf).map_err(connection_lost)
    }
}

/// Everything a `BodyReader` reads comes from the socket, so an error that is
/// neither one of ours nor a timeout means the connection failed.
fn connection_lost(e: io::Error) -> io::Error {
    if e.get_ref().is_some_and(|inner| inner.is::<BodyError>()) || is_timeout(&e) {
        return e;
    }
    // rustls's own text for this one carries a documentation link.
    let why = if e.kind() == io::ErrorKind::UnexpectedEof {
        "the connection closed without TLS close_notify".to_string()
    } else {
        e.to_string()
    };
    BodyError::ConnectionLost(why).into_io()
}

impl<R: BufRead> BodyReader<'_, R> {
    fn read_framed(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.chunk.is_some() {
            return self.chunked(buf);
        }
        if self.length_left == 0 {
            return Ok(0);
        }
        let n = self.data(buf, self.length_left, "truncated request body")?;
        self.length_left -= n as u64;
        Ok(n)
    }
}

/// Read a whole small body (`/Discover`, `/Ask`) under `limit`.
pub fn read_small_body(
    r: &mut impl BufRead,
    headers: &Headers,
    limit: u64,
) -> Result<Vec<u8>, BodyError> {
    let plan = body_plan(headers, limit)?;
    let mut deadline = ReadDeadline::new();
    let mut body = Vec::new();
    let mut reader = BodyReader::new(r, plan, limit, &mut deadline);
    match reader.read_to_end(&mut body) {
        Ok(_) => Ok(body),
        Err(e) => match BodyError::classify(e) {
            Ok(err) => Err(err),
            Err(e) => Err(BodyError::Invalid(format!("request body read failed: {e}"))),
        },
    }
}

/// A parsed request head.
#[derive(Clone, Debug)]
pub struct Request {
    pub method: String,
    /// The request target; leading `//` collapsed to `/`, as `http.server` does.
    pub path: String,
    /// `HTTP/1.x` minor version.
    pub minor: u8,
    /// The request line without its line ending, for the access log.
    pub request_line: String,
    pub headers: Headers,
}

impl Request {
    /// Keep-alive after this request? HTTP/1.1 unless `Connection: close`;
    /// HTTP/1.0 only with `Connection: keep-alive`.
    pub fn keep_alive(&self) -> bool {
        match self
            .headers
            .get("Connection")
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("close") => false,
            Some("keep-alive") => true,
            _ => self.minor >= 1,
        }
    }
}

/// Why no request could be read.
#[derive(Debug)]
pub enum HeadError {
    /// The peer closed the connection (or sent an empty line) between requests.
    Closed,
    /// The socket failed or timed out.
    Io(io::Error),
    /// A malformed head: answer `status` with `message`, then close.
    Bad {
        status: u16,
        message: String,
        request_line: String,
    },
}

fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| char::from(b)).collect()
}

/// Read and parse one request head under Python's `http.server` limits.
pub fn read_request(r: &mut impl BufRead) -> Result<Request, HeadError> {
    let first = read_line(r, MAX_LINE_BYTES + 1).map_err(HeadError::Io)?;
    if first.is_empty() {
        return Err(HeadError::Closed);
    }
    let request_line = latin1(first.strip_suffix(b"\n").unwrap_or(&first))
        .trim_end_matches('\r')
        .to_string();
    if first.len() > MAX_LINE_BYTES {
        return Err(HeadError::Bad {
            status: 414,
            message: "Request-URI Too Long".into(),
            request_line: String::new(),
        });
    }
    if request_line.trim().is_empty() {
        return Err(HeadError::Closed);
    }
    let mut head = first;
    let mut lines = 0;
    loop {
        let line = read_line(r, MAX_LINE_BYTES + 1).map_err(HeadError::Io)?;
        if line.len() > MAX_LINE_BYTES {
            return Err(HeadError::Bad {
                status: 431,
                message: "Line too long".into(),
                request_line,
            });
        }
        let end = line.is_empty() || line == b"\r\n" || line == b"\n";
        head.extend_from_slice(&line);
        if end {
            break;
        }
        lines += 1;
        if lines > MAX_HEADERS {
            return Err(HeadError::Bad {
                status: 431,
                message: "Too many headers".into(),
                request_line,
            });
        }
    }
    if !head.ends_with(b"\n\n") && !head.ends_with(b"\n\r\n") {
        // The connection closed inside the head.
        return Err(HeadError::Closed);
    }
    let bad = |request_line: String| HeadError::Bad {
        status: 400,
        message: format!("Bad request syntax ({})", py_repr(&request_line)),
        request_line,
    };
    let mut slots = [httparse::EMPTY_HEADER; MAX_HEADERS + 1];
    let mut req = httparse::Request::new(&mut slots);
    match req.parse(&head) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => return Err(bad(request_line)),
    }
    let (Some(method), Some(target), Some(minor)) = (req.method, req.path, req.version) else {
        return Err(bad(request_line));
    };
    let path = if target.starts_with("//") {
        format!("/{}", target.trim_start_matches('/'))
    } else {
        target.to_string()
    };
    let headers = Headers(
        req.headers
            .iter()
            .map(|h| (h.name.to_string(), latin1(h.value)))
            .collect(),
    );
    Ok(Request {
        method: method.to_string(),
        path,
        minor,
        request_line,
        headers,
    })
}

/// The reason phrase Python's `http.server` sends.
pub fn reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        408 => "Request Timeout",
        413 => "Content Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Content",
        431 => "Request Header Fields Too Large",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        507 => "Insufficient Storage",
        _ => "",
    }
}

/// An RFC 9110 IMF-fixdate, for the `Date` header.
pub fn http_date(t: SystemTime) -> String {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        WEEKDAYS.get(days.rem_euclid(7) as usize).unwrap_or(&"Thu"),
        day,
        MONTHS.get((month - 1) as usize).unwrap_or(&"Jan"),
        year,
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Write a response: status line, `Date`, `headers`, then `body`, flushed.
pub fn write_response(
    w: &mut impl Write,
    status: u16,
    headers: &[(&str, &str)],
    body: &[u8],
) -> io::Result<()> {
    let mut out = format!("HTTP/1.1 {status} {}\r\n", reason(status));
    if status >= 200 {
        out.push_str(&format!("Date: {}\r\n", http_date(SystemTime::now())));
    }
    for (k, v) in headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body);
    w.write_all(&bytes)?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> Headers {
        Headers(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }

    /// Hands out `data`, then times out on every read, as a socket would.
    struct ThenQuiet<'a>(&'a [u8]);
    impl Read for ThenQuiet<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.0.is_empty() {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "quiet"));
            }
            let n = buf.len().min(self.0.len());
            buf[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Ok(n)
        }
    }

    /// Reads a chunked body that goes quiet after `input`, with Patience
    /// whose archive always claims to be whole. The error, and how many
    /// times completeness was asked.
    fn patient_read(input: &[u8]) -> (io::Error, usize) {
        let mut r = io::BufReader::new(ThenQuiet(input));
        let mut deadline = ReadDeadline::new();
        let asked = std::cell::Cell::new(0);
        let complete = || {
            asked.set(asked.get() + 1);
            true
        };
        let set_wait = |_: Option<Duration>| {};
        let mut body = BodyReader::new(&mut r, BodyPlan::Chunked, 1 << 20, &mut deadline)
            .with_patience(Patience {
                step: Duration::from_secs(3),
                limit: Duration::from_secs(30),
                set_wait: &set_wait,
                is_complete: &complete,
            });
        let e = io::copy(&mut body, &mut io::sink()).unwrap_err();
        (e, asked.get())
    }

    #[test]
    fn only_a_quiet_chunk_boundary_can_end_a_body_as_complete() {
        // Quiet where the next chunk-size line would start: the body ends.
        let (e, asked) = patient_read(b"3\r\nabc\r\n");
        assert!(is_complete(&e), "{e}");
        assert_eq!(asked, 1);
        // Quiet inside a chunk's data: an ordinary stall, never "complete".
        let (e, asked) = patient_read(b"a\r\nabc");
        assert!(is_timeout(&e) && !is_complete(&e), "{e}");
        assert_eq!(asked, 0);
    }

    fn body(input: &[u8], h: &[(&str, &str)], limit: u64) -> (Result<Vec<u8>, BodyError>, Vec<u8>) {
        let mut r = io::BufReader::new(input);
        let plan = match body_plan(&headers(h), limit) {
            Ok(p) => p,
            Err(e) => return (Err(e), Vec::new()),
        };
        let mut deadline = ReadDeadline::new();
        let mut out = Vec::new();
        let mut reader = BodyReader::new(&mut r, plan, limit, &mut deadline);
        let result = io::copy(&mut reader, &mut out).map_err(|e| BodyError::classify(e).unwrap());
        (result.map(|_| out.clone()), out)
    }

    #[test]
    fn content_length_over_limit_is_rejected_before_the_body_is_read() {
        let (r, out) = body(b"abcde", &[("Content-Length", "5")], 4);
        assert!(
            matches!(r, Err(BodyError::TooLarge(m)) if m == "request body exceeds 4-byte limit")
        );
        assert!(out.is_empty());
    }

    #[test]
    fn chunked_body_stops_before_the_chunk_that_crosses_the_limit() {
        let (r, out) = body(
            b"4\r\nabcd\r\n4\r\nefgh\r\n0\r\n\r\n",
            &[("Transfer-Encoding", "chunked")],
            7,
        );
        assert!(matches!(r, Err(BodyError::TooLarge(_))));
        assert_eq!(out, b"abcd");
    }

    #[test]
    fn chunked_bodies_with_extensions_and_trailers_decode() {
        let input = b"4;name=v\r\nabcd\r\nA\r\n0123456789\r\n0\r\nX-Trailer: 1\r\n\r\nNEXT";
        let mut r = io::BufReader::new(&input[..]);
        let mut deadline = ReadDeadline::new();
        let mut out = Vec::new();
        BodyReader::new(&mut r, BodyPlan::Chunked, 100, &mut deadline)
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, b"abcd0123456789");
        // The next request on the connection is untouched.
        let mut rest = Vec::new();
        r.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"NEXT");
    }

    #[test]
    fn malformed_framing_is_refused() {
        let chunked = &[("Transfer-Encoding", "chunked")][..];
        let long_line = format!("{}\r\n", "0".repeat(200));
        let many_trailers = format!("0\r\n{}\r\n", "X-T: 1\r\n".repeat(2000));
        type Case<'a> = (&'a [u8], &'a [(&'a str, &'a str)], &'a str);
        let cases: Vec<Case> = vec![
            (b"zz\r\n", chunked, "invalid chunk size: b'zz'"),
            (b"-1\r\nx\r\n", chunked, "invalid chunk size"),
            (b"0x4\r\nabcd\r\n0\r\n\r\n", chunked, "invalid chunk size"),
            (
                long_line.as_bytes(),
                chunked,
                "invalid or overlong chunk-size line",
            ),
            (b"4\r\nab", chunked, "truncated chunk data"),
            (b"4\r\nabcdXX0\r\n\r\n", chunked, "chunk data missing CRLF"),
            (
                b"0\r\nX: 1\r\n",
                chunked,
                "invalid or overlong chunk trailers",
            ),
            (
                many_trailers.as_bytes(),
                chunked,
                "invalid or overlong chunk trailers",
            ),
            (b"", chunked, "invalid or overlong chunk-size line"),
            (b"abc", &[("Content-Length", "5")], "truncated request body"),
            (
                b"",
                &[],
                "request body needs Content-Length or chunked encoding",
            ),
            (
                b"",
                &[("Content-Length", "-1")],
                "invalid Content-Length: '-1'",
            ),
            (b"", &[("Content-Length", "1_0")], "invalid Content-Length"),
            (b"", &[("Content-Length", "+5")], "invalid Content-Length"),
            (
                b"",
                &[("Content-Length", "5"), ("content-length", "5")],
                "repeated Content-Length header",
            ),
            (
                b"",
                &[("Transfer-Encoding", "gzip, chunked")],
                "unsupported Transfer-Encoding: 'gzip, chunked'",
            ),
        ];
        for (input, h, want) in cases {
            match body(input, h, 1 << 20).0 {
                Err(BodyError::Invalid(m)) => assert!(m.contains(want), "{m:?} lacks {want:?}"),
                other => panic!("{want}: {other:?}"),
            }
        }
        let huge = b"ffffffffffffffffffffff\r\n";
        assert!(matches!(
            body(huge, chunked, 10).0,
            Err(BodyError::TooLarge(_))
        ));
        assert_eq!(
            body(
                b"5\r\nhello\r\n0\r\n\r\n",
                &[("Transfer-Encoding", "Chunked"), ("Content-Length", "99")],
                10
            )
            .0
            .unwrap(),
            b"hello"
        );
    }

    #[test]
    fn a_body_that_misses_its_progress_deadline_is_rejected() {
        let started = Instant::now()
            .checked_sub(Duration::from_secs_f64(INITIAL_READ_SECONDS + 1.0))
            .unwrap();
        let mut deadline = ReadDeadline::started_at(started);
        let mut r = io::BufReader::new(&b"x"[..]);
        let err = BodyReader::new(&mut r, BodyPlan::Length(1), 1, &mut deadline)
            .read_to_end(&mut Vec::new())
            .unwrap_err();
        assert!(matches!(
            BodyError::classify(err),
            Ok(BodyError::Timeout(Stall::Rate))
        ));
        let report = deadline.stall_report(Stall::Rate, Some(10));
        assert!(
            report.starts_with(
                "request body read timed out, slower than 65536 bytes/s: 1 of 10 bytes in 61."
            ),
            "{report}"
        );
        let idle = ReadDeadline::new().stall_report(Stall::Idle, None);
        assert!(
            idle.starts_with(
                "request body read timed out, nothing arrived for 30 s: 0 bytes in 0."
            ),
            "{idle}"
        );
    }

    #[test]
    fn socket_timeouts_classify_as_idle_stalls() {
        let e = io::Error::new(
            io::ErrorKind::WouldBlock,
            "Resource temporarily unavailable",
        );
        assert!(matches!(
            BodyError::classify(e),
            Ok(BodyError::Timeout(Stall::Idle))
        ));
        let e = io::Error::new(io::ErrorKind::ConnectionReset, "reset");
        assert!(BodyError::classify(e).is_err());
    }

    /// A socket that delivers some of a body, then fails with `kind`.
    struct FailsAfter {
        sent: bool,
        kind: io::ErrorKind,
    }

    impl Read for FailsAfter {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if std::mem::replace(&mut self.sent, true) {
                return Err(io::Error::new(self.kind, "socket failed"));
            }
            buf[..10].fill(b'x');
            Ok(10)
        }
    }

    #[test]
    fn a_connection_that_fails_mid_body_is_lost_not_a_disk_error() {
        // Everything a body reader reads is the socket's, so any failure
        // there means the sender has gone (plugin #90). A timeout is still a
        // stall, and an error that never passed through a body reader is
        // still the disk's.
        use io::ErrorKind::*;
        for kind in [
            ConnectionReset,
            ConnectionAborted,
            BrokenPipe,
            UnexpectedEof,
            InvalidData,
            WouldBlock,
        ] {
            let mut sock = io::BufReader::new(FailsAfter { sent: false, kind });
            let mut deadline = ReadDeadline::new();
            let mut body = BodyReader::new(&mut sock, BodyPlan::Length(100), 100, &mut deadline);
            let e = io::copy(&mut body, &mut io::sink()).unwrap_err();
            match BodyError::classify(e) {
                Ok(BodyError::Timeout(Stall::Idle)) => assert_eq!(kind, WouldBlock),
                Ok(BodyError::ConnectionLost(m)) => {
                    assert_ne!(kind, WouldBlock);
                    let why = if kind == UnexpectedEof {
                        "the connection closed without TLS close_notify"
                    } else {
                        "socket failed"
                    };
                    assert_eq!(m, why);
                }
                other => panic!("{kind:?}: {other:?}"),
            }
        }
        let headers = Headers(vec![("Content-Length".into(), "100".into())]);
        let mut sock = io::BufReader::new(FailsAfter {
            sent: false,
            kind: ConnectionReset,
        });
        assert!(matches!(
            read_small_body(&mut sock, &headers, 100),
            Err(BodyError::ConnectionLost(_))
        ));
    }

    #[test]
    fn request_heads_parse_under_limits() {
        let mut r = io::BufReader::new(&b"POST //Upload HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-dvzip\r\nTransferID: \xe9\r\n\r\nBODY"[..]);
        let req = read_request(&mut r).unwrap();
        assert_eq!(
            (req.method.as_str(), req.path.as_str(), req.minor),
            ("POST", "/Upload", 1)
        );
        assert_eq!(req.request_line, "POST //Upload HTTP/1.1");
        assert_eq!(req.headers.get("content-type"), Some("application/x-dvzip"));
        assert_eq!(req.headers.get("TransferID"), Some("é"));
        assert!(req.keep_alive());

        assert!(matches!(
            read_request(&mut io::BufReader::new(&b""[..])),
            Err(HeadError::Closed)
        ));
        assert!(matches!(
            read_request(&mut io::BufReader::new(&b"GET / HTTP/1.1\r\nHost"[..])),
            Err(HeadError::Closed)
        ));
        let garbage = read_request(&mut io::BufReader::new(
            &b"\x16\x03\x01 nonsense\r\n\r\n"[..],
        ));
        assert!(matches!(garbage, Err(HeadError::Bad { status: 400, .. })));
        let many = format!("GET / HTTP/1.1\r\n{}\r\n", "X: y\r\n".repeat(101));
        assert!(matches!(
            read_request(&mut io::BufReader::new(many.as_bytes())),
            Err(HeadError::Bad { status: 431, .. })
        ));
        let long = format!("GET /{} HTTP/1.1\r\n\r\n", "a".repeat(70_000));
        assert!(matches!(
            read_request(&mut io::BufReader::new(long.as_bytes())),
            Err(HeadError::Bad { status: 414, .. })
        ));
        let close = read_request(&mut io::BufReader::new(&b"GET / HTTP/1.0\r\n\r\n"[..])).unwrap();
        assert!(!close.keep_alive());
    }

    #[test]
    fn dates_are_imf_fixdate() {
        assert_eq!(http_date(UNIX_EPOCH), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(
            http_date(UNIX_EPOCH + Duration::from_secs(1_791_668_400)),
            "Sat, 10 Oct 2026 21:40:00 GMT"
        );
    }
}
