//! HTTPS/1.1 to one AirDrop receiver: a keep-alive TLS connection that
//! carries POSTs, the way Python's `http.client.HTTPSConnection` did for
//! airdrop-send.py.
//!
//! Every socket operation is bounded. 021922Z: our third-leg ACK and TLS
//! Client Hello were emitted and lost, the Mac retransmitted SYN-ACK 13 times,
//! and TCP backed off to rto:120000. With no timeout the client sat in that
//! backoff for 4.5 minutes, past the end of the watched hold, instead of
//! failing and reporting. A wedged send must cost seconds, not a hold. An
//! optional absolute deadline caps the whole exchange as well (send-to-peer's
//! name lookups, which Python bounded with a subprocess timeout).

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};

use crate::error::PyErr;

/// Responses are small plists (a Mac's /Discover answer is ~4 KB with its
/// record); anything far larger is not an AirDrop receiver talking.
const MAX_RESPONSE_BYTES: usize = 4 << 20;
const MAX_HEAD_BYTES: usize = 64 << 10;
/// Chunk size for a streamed (chunked) request body.
const CHUNK_BYTES: usize = 64 << 10;

/// The Upload socket's cap on TCP's retransmission timeout (#79): through an
/// AWDL blackout, keep retrying every 1.3 s instead of backing off to minutes,
/// so the first frame after the peer returns is answered.
const UPLOAD_RTO_MAX_MS: libc::c_int = 1300;
/// How long the capped Upload keeps retrying without an ACK: without it, the
/// kernel's tcp_retries2 model gives a 1.3 s cap only about 18 s.
const UPLOAD_USER_TIMEOUT_MS: libc::c_int = 120_000;
/// From linux/tcp.h (Linux 6.15); libc does not define it yet.
const TCP_RTO_MAX_MS: libc::c_int = 44;

/// IPPROTO_TCP integer options, so the cap's rollback can be tested without a kernel.
trait TcpOpts {
    fn get(&self, name: libc::c_int) -> io::Result<libc::c_int>;
    fn set(&self, name: libc::c_int, value: libc::c_int) -> io::Result<()>;
}

impl TcpOpts for TcpStream {
    fn get(&self, name: libc::c_int) -> io::Result<libc::c_int> {
        let mut got: libc::c_int = 0;
        let mut len = size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: a live TCP socket owned by `self`; `got` and `len` are valid for writes.
        let rc = unsafe {
            libc::getsockopt(
                self.as_raw_fd(),
                libc::IPPROTO_TCP,
                name,
                (&raw mut got).cast(),
                &raw mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(got)
    }

    fn set(&self, name: libc::c_int, value: libc::c_int) -> io::Result<()> {
        // SAFETY: as above; the buffer is a local c_int.
        let rc = unsafe {
            libc::setsockopt(
                self.as_raw_fd(),
                libc::IPPROTO_TCP,
                name,
                (&raw const value).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// How the Upload socket's retransmissions ended up.
#[derive(Debug)]
pub enum UploadTcp {
    Capped,
    /// Unchanged kernel defaults, verified; why the cap was not applied.
    Stock(io::Error),
}

fn set_verified(sock: &impl TcpOpts, name: libc::c_int, value: libc::c_int) -> io::Result<()> {
    sock.set(name, value)?;
    let got = sock.get(name)?;
    if got != value {
        return Err(io::Error::other(format!(
            "TCP option {name} reads back {got}, not {value}"
        )));
    }
    Ok(())
}

/// The user timeout and the RTO cap together, or neither. A kernel that can't
/// read either option is left untouched. A failure part-way restores both
/// original values and verifies them; an error means the socket is in neither
/// state and must not carry the Upload.
fn bound_upload_retransmits(sock: &impl TcpOpts) -> io::Result<UploadTcp> {
    let (rto, user) = match (sock.get(TCP_RTO_MAX_MS), sock.get(libc::TCP_USER_TIMEOUT)) {
        (Ok(r), Ok(u)) => (r, u),
        (Err(e), _) | (_, Err(e)) => return Ok(UploadTcp::Stock(e)),
    };
    let applied = set_verified(sock, libc::TCP_USER_TIMEOUT, UPLOAD_USER_TIMEOUT_MS)
        .and_then(|()| set_verified(sock, TCP_RTO_MAX_MS, UPLOAD_RTO_MAX_MS));
    let Err(why) = applied else {
        return Ok(UploadTcp::Capped);
    };
    let restored = set_verified(sock, TCP_RTO_MAX_MS, rto);
    let restored = set_verified(sock, libc::TCP_USER_TIMEOUT, user).and(restored);
    match restored {
        Ok(()) => Ok(UploadTcp::Stock(why)),
        Err(e) => Err(io::Error::other(format!(
            "the Upload socket's retransmission options are half-set ({why}) and could not be restored: {e}"
        ))),
    }
}

/// A receiver's address, and the host text Python used for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub addr: SocketAddr,
    /// `fe80::1%awdl0`, `::1`, `127.0.0.1`: what the `Host` header carries.
    pub host: String,
}

impl Endpoint {
    /// An IP literal, optionally with a `%zone`, on `port`. A link-local
    /// address without a zone is ambiguous, so it gets `iface`'s (fe80::1 ->
    /// fe80::1%awdl0). Host names are refused, as Python's `ip_address()`
    /// refused them.
    pub fn resolve(host: &str, port: u16, iface: &str) -> io::Result<Endpoint> {
        let (addr_text, zone) = match host.split_once('%') {
            Some((a, z)) => (a, Some(z)),
            None => (host, None),
        };
        let bad = || {
            PyErr::new(
                "ValueError",
                &format!("{host:?} does not appear to be an IPv4 or IPv6 address"),
            )
            .into_io()
        };
        let ip: IpAddr = addr_text.parse().map_err(|_| bad())?;
        match ip {
            IpAddr::V4(v4) => {
                if zone.is_some() {
                    return Err(bad());
                }
                Ok(Endpoint {
                    addr: SocketAddr::new(IpAddr::V4(v4), port),
                    host: v4.to_string(),
                })
            }
            IpAddr::V6(v6) => {
                let zone = match zone {
                    Some(z) => Some(z.to_owned()),
                    None if v6.is_unicast_link_local() => Some(iface.to_owned()),
                    None => None,
                };
                Self::v6(v6, port, zone.as_deref())
            }
        }
    }

    /// An IPv6 address with an optional zone (interface name or index).
    pub fn v6(addr: Ipv6Addr, port: u16, zone: Option<&str>) -> io::Result<Endpoint> {
        let (scope, host) = match zone {
            Some(z) => {
                let scope = match z.parse::<u32>() {
                    Ok(n) => n,
                    Err(_) => omdrop_proto::net::scope_id(z)?,
                };
                (scope, format!("{addr}%{z}"))
            }
            None => (0, addr.to_string()),
        };
        Ok(Endpoint {
            addr: SocketAddr::V6(SocketAddrV6::new(addr, port, 0, scope)),
            host,
        })
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// The `Host` header value, as http.client built it.
    pub fn host_header(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port() == 443 {
            host
        } else {
            format!("{host}:{}", self.port())
        }
    }
}

/// The socket under TLS, with per-operation timeouts capped by a deadline.
#[derive(Debug)]
struct Timed {
    sock: TcpStream,
    op: Option<Duration>,
    deadline: Option<Instant>,
}

impl Timed {
    /// Arm the socket for one operation. Without a deadline the timeouts set
    /// in [`Timed::set_op`] stand.
    fn arm(&self, read: bool) -> io::Result<()> {
        let Some(deadline) = self.deadline else {
            return Ok(());
        };
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(PyErr::new("TimeoutError", "timed out").into_io());
        }
        let t = Some(self.op.map_or(left, |op| op.min(left)));
        if read {
            self.sock.set_read_timeout(t)
        } else {
            self.sock.set_write_timeout(t)
        }
    }

    fn set_op(&mut self, op: Option<Duration>) -> io::Result<()> {
        self.op = op;
        self.sock.set_read_timeout(op)?;
        self.sock.set_write_timeout(op)
    }
}

impl Read for Timed {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.arm(true)?;
        self.sock.read(buf)
    }
}

impl Write for Timed {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.arm(false)?;
        self.sock.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sock.flush()
    }
}

/// A request body.
pub enum Body<'a> {
    /// Sent with a Content-Length.
    Bytes(&'a [u8]),
    /// Sent chunked, as sharingd sends /Upload: the closure writes the body.
    Stream(&'a mut dyn FnMut(&mut dyn Write) -> io::Result<()>),
}

/// One response, read in full.
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub reason: String,
    pub body: Vec<u8>,
}

/// A keep-alive HTTPS connection.
pub struct Conn {
    stream: StreamOwned<ClientConnection, Timed>,
    rbuf: Vec<u8>,
    /// The server said `Connection: close`, or the body ran to EOF.
    pub closed: bool,
}

impl Conn {
    /// TCP connect and complete the TLS handshake, each operation bounded by
    /// `op` and everything by `deadline`. A peer's certificate is accepted
    /// whoever signed it (see `omdrop_proto::tls`).
    pub fn open(
        endpoint: &Endpoint,
        tls: &Arc<ClientConfig>,
        op: Option<Duration>,
        deadline: Option<Instant>,
    ) -> io::Result<Conn> {
        let budget = match (op, deadline) {
            (op, Some(d)) => {
                let left = d.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(PyErr::new("TimeoutError", "timed out").into_io());
                }
                Some(op.map_or(left, |o| o.min(left)))
            }
            (op, None) => op,
        };
        let sock = match budget {
            Some(t) => TcpStream::connect_timeout(&endpoint.addr, t)?,
            None => TcpStream::connect(endpoint.addr)?,
        };
        // Each request is written whole and then answered; Nagle would hold a
        // trailing TLS record for the peer's delayed ACK (measured on
        // loopback: /Discover 0.09 s with Nagle, 0.04 s without).
        sock.set_nodelay(true)?;
        let mut timed = Timed {
            sock,
            op: None,
            deadline,
        };
        timed.set_op(op)?;
        // No SNI: the name is an address, as it was for Python.
        let name = ServerName::IpAddress(endpoint.addr.ip().into());
        let conn = ClientConnection::new(tls.clone(), name).map_err(io::Error::other)?;
        let mut stream = StreamOwned::new(conn, timed);
        while stream.conn.is_handshaking() {
            stream.conn.complete_io(&mut stream.sock)?;
        }
        Ok(Conn {
            stream,
            rbuf: Vec::new(),
            closed: false,
        })
    }

    /// Change the per-operation timeout (the Ask's long one, which then holds
    /// for the Upload on the same connection, as `sock.settimeout` did).
    pub fn set_op_timeout(&mut self, op: Option<Duration>) -> io::Result<()> {
        self.stream.sock.set_op(op)
    }

    /// Bound this connection's retransmissions for the Upload (#79).
    pub fn bound_upload_retransmits(&self) -> io::Result<UploadTcp> {
        bound_upload_retransmits(&self.stream.sock.sock)
    }

    /// POST and read the whole answer.
    pub fn post(
        &mut self,
        path: &str,
        host_header: &str,
        headers: &[(&str, String)],
        body: Body<'_>,
    ) -> io::Result<Response> {
        // http.client's order: request line, Host, the framing header, then
        // the caller's headers.
        let mut head = format!("POST {path} HTTP/1.1\r\nHost: {host_header}\r\n");
        match &body {
            Body::Bytes(b) => head.push_str(&format!("Content-Length: {}\r\n", b.len())),
            Body::Stream(_) => head.push_str("Transfer-Encoding: chunked\r\n"),
        }
        for (k, v) in headers {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        head.push_str("\r\n");
        match body {
            Body::Bytes(b) => {
                let mut all = head.into_bytes();
                all.extend_from_slice(b);
                self.stream.write_all(&all)?;
            }
            Body::Stream(produce) => {
                self.stream.write_all(head.as_bytes())?;
                let mut chunked = Chunked {
                    inner: &mut self.stream,
                    buf: Vec::with_capacity(CHUNK_BYTES),
                };
                produce(&mut chunked)?;
                chunked.finish()?;
            }
        }
        self.stream.flush()?;
        self.read_response()
    }

    fn fill(&mut self) -> io::Result<usize> {
        let mut chunk = [0u8; 16 << 10];
        let n = self.stream.read(&mut chunk)?;
        self.rbuf
            .extend_from_slice(chunk.get(..n).unwrap_or_default());
        Ok(n)
    }

    fn read_response(&mut self) -> io::Result<Response> {
        loop {
            let (status, reason, head_len, framing, close) = self.read_head()?;
            self.rbuf.drain(..head_len);
            // http.client skips interim 100 Continue answers.
            if (100..200).contains(&status) {
                continue;
            }
            let body = match framing {
                Framing::None => Vec::new(),
                Framing::Length(n) => self.read_exact_body(n)?,
                Framing::Chunked => self.read_chunked()?,
                Framing::UntilClose => {
                    self.closed = true;
                    self.read_to_close()?
                }
            };
            if close {
                self.closed = true;
            }
            return Ok(Response {
                status,
                reason,
                body,
            });
        }
    }

    fn read_head(&mut self) -> io::Result<(u16, String, usize, Framing, bool)> {
        loop {
            let mut headers = [httparse::EMPTY_HEADER; 64];
            let mut resp = httparse::Response::new(&mut headers);
            match resp.parse(&self.rbuf) {
                Ok(httparse::Status::Complete(n)) => {
                    let status = resp.code.unwrap_or(0);
                    let reason = resp.reason.unwrap_or("").to_owned();
                    let http10 = resp.version == Some(0);
                    let mut length = None;
                    let mut chunked = false;
                    let mut conn_close = http10;
                    for h in resp.headers.iter() {
                        let value = String::from_utf8_lossy(h.value);
                        if h.name.eq_ignore_ascii_case("content-length") {
                            let n: usize = value
                                .trim()
                                .parse()
                                .map_err(|_| bad_status("invalid Content-Length"))?;
                            length = Some(n);
                        } else if h.name.eq_ignore_ascii_case("transfer-encoding") {
                            chunked = value
                                .split(',')
                                .next_back()
                                .is_some_and(|t| t.trim().eq_ignore_ascii_case("chunked"));
                        } else if h.name.eq_ignore_ascii_case("connection") {
                            for token in value.split(',') {
                                let token = token.trim();
                                if token.eq_ignore_ascii_case("close") {
                                    conn_close = true;
                                } else if token.eq_ignore_ascii_case("keep-alive") && http10 {
                                    conn_close = false;
                                }
                            }
                        }
                    }
                    let framing = if status == 204 || status == 304 || (100..200).contains(&status)
                    {
                        Framing::None
                    } else if chunked {
                        Framing::Chunked
                    } else if let Some(n) = length {
                        if n > MAX_RESPONSE_BYTES {
                            return Err(PyErr::new(
                                "HTTPException",
                                &format!("response of {n} bytes is too large"),
                            )
                            .into_io());
                        }
                        Framing::Length(n)
                    } else {
                        Framing::UntilClose
                    };
                    return Ok((status, reason, n, framing, conn_close));
                }
                Ok(httparse::Status::Partial) => {
                    if self.rbuf.len() > MAX_HEAD_BYTES {
                        return Err(PyErr::new("LineTooLong", "response head too long").into_io());
                    }
                }
                Err(e) => return Err(bad_status(&e.to_string())),
            }
            let had = self.rbuf.len();
            let n = match self.fill() {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => 0,
                Err(e) => return Err(e),
            };
            if n == 0 {
                self.closed = true;
                return Err(if had == 0 {
                    PyErr::new(
                        "RemoteDisconnected",
                        "Remote end closed connection without response",
                    )
                    .into_io()
                } else {
                    PyErr::new(
                        "IncompleteRead",
                        "connection closed inside the response head",
                    )
                    .into_io()
                });
            }
        }
    }

    fn read_exact_body(&mut self, n: usize) -> io::Result<Vec<u8>> {
        while self.rbuf.len() < n {
            if self.fill_or_eof()? == 0 {
                self.closed = true;
                return Err(PyErr::new(
                    "IncompleteRead",
                    &format!(
                        "{} bytes read, {} more expected",
                        self.rbuf.len(),
                        n - self.rbuf.len()
                    ),
                )
                .into_io());
            }
        }
        Ok(self.rbuf.drain(..n).collect())
    }

    fn read_line(&mut self) -> io::Result<String> {
        loop {
            if let Some(i) = self.rbuf.windows(2).position(|w| w == b"\r\n") {
                let line: Vec<u8> = self.rbuf.drain(..i + 2).collect();
                return Ok(String::from_utf8_lossy(line.get(..i).unwrap_or_default()).into_owned());
            }
            if self.rbuf.len() > MAX_HEAD_BYTES {
                return Err(PyErr::new("LineTooLong", "chunk line too long").into_io());
            }
            if self.fill_or_eof()? == 0 {
                self.closed = true;
                return Err(PyErr::new(
                    "IncompleteRead",
                    "connection closed inside a chunked body",
                )
                .into_io());
            }
        }
    }

    fn read_chunked(&mut self) -> io::Result<Vec<u8>> {
        let mut body = Vec::new();
        loop {
            let line = self.read_line()?;
            let size_text = line.split(';').next().unwrap_or("").trim();
            let size = usize::from_str_radix(size_text, 16)
                .map_err(|_| PyErr::new("IncompleteRead", "invalid chunk size").into_io())?;
            if size == 0 {
                // Trailers, up to the empty line.
                while !self.read_line()?.is_empty() {}
                return Ok(body);
            }
            if body.len().saturating_add(size) > MAX_RESPONSE_BYTES {
                return Err(PyErr::new("HTTPException", "chunked response is too large").into_io());
            }
            let chunk = self.read_exact_body(size)?;
            body.extend_from_slice(&chunk);
            if !self.read_line()?.is_empty() {
                return Err(PyErr::new("IncompleteRead", "chunk not followed by CRLF").into_io());
            }
        }
    }

    fn read_to_close(&mut self) -> io::Result<Vec<u8>> {
        while self.fill_or_eof()? > 0 {
            if self.rbuf.len() > MAX_RESPONSE_BYTES {
                return Err(PyErr::new("HTTPException", "response is too large").into_io());
            }
        }
        Ok(std::mem::take(&mut self.rbuf))
    }

    /// A read where a TLS close without close_notify counts as EOF, as
    /// Python's `suppress_ragged_eofs` made it.
    fn fill_or_eof(&mut self) -> io::Result<usize> {
        match self.fill() {
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(0),
            other => other,
        }
    }
}

enum Framing {
    None,
    Length(usize),
    Chunked,
    UntilClose,
}

fn bad_status(why: &str) -> io::Error {
    PyErr::new("BadStatusLine", why).into_io()
}

/// HTTP/1.1 chunked transfer coding over a writer.
struct Chunked<'a, W: Write> {
    inner: &'a mut W,
    buf: Vec<u8>,
}

impl<W: Write> Chunked<'_, W> {
    fn emit(&mut self) -> io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let mut frame = format!("{:x}\r\n", self.buf.len()).into_bytes();
        frame.extend_from_slice(&self.buf);
        frame.extend_from_slice(b"\r\n");
        self.inner.write_all(&frame)?;
        self.buf.clear();
        Ok(())
    }

    fn finish(mut self) -> io::Result<()> {
        self.emit()?;
        self.inner.write_all(b"0\r\n\r\n")
    }
}

impl<W: Write> Write for Chunked<'_, W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let room = CHUNK_BYTES - self.buf.len();
        let n = room.min(data.len());
        self.buf
            .extend_from_slice(data.get(..n).unwrap_or_default());
        if self.buf.len() >= CHUNK_BYTES {
            self.emit()?;
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn endpoints_carry_the_zone_python_gave_them() {
        let lo = Endpoint::resolve("::1", 8771, "awdl0").unwrap();
        assert_eq!(lo.host_header(), "[::1]:8771");
        let v4 = Endpoint::resolve("127.0.0.1", 443, "awdl0").unwrap();
        assert_eq!(v4.host_header(), "127.0.0.1");
        // A numeric zone needs no interface lookup.
        let ll = Endpoint::resolve("fe80::e09d:3ff:fe6c:5823%7", 8770, "awdl0").unwrap();
        assert_eq!(ll.host_header(), "[fe80::e09d:3ff:fe6c:5823%7]:8770");
        match ll.addr {
            SocketAddr::V6(a) => assert_eq!(a.scope_id(), 7),
            SocketAddr::V4(_) => panic!("v4"),
        }
        let lo_iface = Endpoint::resolve("fe80::1", 1, "lo").unwrap();
        assert_eq!(lo_iface.host, "fe80::1%lo");
        let err = Endpoint::resolve("localhost", 1, "lo").unwrap_err();
        assert_eq!(PyErr::from_io(&err).class, "ValueError");
        assert!(Endpoint::resolve("127.0.0.1%lo", 1, "lo").is_err());
    }

    #[test]
    fn chunked_framing() {
        let mut out = Vec::new();
        let mut c = Chunked {
            inner: &mut out,
            buf: Vec::new(),
        };
        c.write_all(b"hello").unwrap();
        c.finish().unwrap();
        assert_eq!(out, b"5\r\nhello\r\n0\r\n\r\n");
    }

    /// A socket whose options live in a map. `fail_get` names an option whose
    /// read errors; `fail_set` an option (and value, or None for any) whose
    /// set errors; `lie` an option that reads back wrong while it holds that value.
    #[derive(Default)]
    struct Fake {
        opts: RefCell<HashMap<libc::c_int, libc::c_int>>,
        fail_get: Option<libc::c_int>,
        fail_set: Option<(libc::c_int, Option<libc::c_int>)>,
        lie: Option<(libc::c_int, libc::c_int)>,
    }

    impl Fake {
        fn stock() -> Fake {
            let f = Fake::default();
            f.opts
                .borrow_mut()
                .extend([(TCP_RTO_MAX_MS, 120_000), (libc::TCP_USER_TIMEOUT, 0)]);
            f
        }
        fn now(&self) -> (libc::c_int, libc::c_int) {
            let o = self.opts.borrow();
            (o[&TCP_RTO_MAX_MS], o[&libc::TCP_USER_TIMEOUT])
        }
    }

    impl TcpOpts for Fake {
        fn get(&self, name: libc::c_int) -> io::Result<libc::c_int> {
            if self.fail_get == Some(name) {
                return Err(io::Error::from_raw_os_error(libc::ENOPROTOOPT));
            }
            let v = self.opts.borrow()[&name];
            Ok(if self.lie == Some((name, v)) {
                v + 1
            } else {
                v
            })
        }
        fn set(&self, name: libc::c_int, value: libc::c_int) -> io::Result<()> {
            if let Some((n, v)) = self.fail_set
                && n == name
                && v.is_none_or(|v| v == value)
            {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }
            self.opts.borrow_mut().insert(name, value);
            Ok(())
        }
    }

    #[test]
    fn upload_retransmits_on_a_real_socket_are_capped_or_left_stock() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let sock = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        match bound_upload_retransmits(&sock).unwrap() {
            UploadTcp::Capped => {
                assert_eq!(sock.get(TCP_RTO_MAX_MS).unwrap(), 1300);
                assert_eq!(sock.get(libc::TCP_USER_TIMEOUT).unwrap(), 120_000);
            }
            UploadTcp::Stock(_) => assert_eq!(sock.get(libc::TCP_USER_TIMEOUT).unwrap(), 0),
        }
    }

    #[test]
    fn a_kernel_without_the_cap_is_left_untouched() {
        let f = Fake {
            fail_get: Some(TCP_RTO_MAX_MS),
            ..Fake::stock()
        };
        assert!(matches!(
            bound_upload_retransmits(&f),
            Ok(UploadTcp::Stock(_))
        ));
        assert_eq!(f.now(), (120_000, 0));
    }

    #[test]
    fn a_failure_part_way_restores_both_options() {
        let cases = [
            Fake {
                lie: Some((TCP_RTO_MAX_MS, 1300)),
                ..Fake::stock()
            },
            Fake {
                lie: Some((libc::TCP_USER_TIMEOUT, 120_000)),
                ..Fake::stock()
            },
            Fake {
                fail_set: Some((TCP_RTO_MAX_MS, Some(1300))),
                ..Fake::stock()
            },
        ];
        for (i, f) in cases.iter().enumerate() {
            assert!(
                matches!(bound_upload_retransmits(f), Ok(UploadTcp::Stock(_))),
                "case {i}"
            );
            assert_eq!(f.now(), (120_000, 0), "case {i}");
        }
    }

    #[test]
    fn a_restore_that_cannot_be_verified_fails_the_upload() {
        // The cap is set, reads back wrong, and then can't be put back to 120000.
        let f = Fake {
            lie: Some((TCP_RTO_MAX_MS, 1300)),
            fail_set: Some((TCP_RTO_MAX_MS, Some(120_000))),
            ..Fake::stock()
        };
        assert!(bound_upload_retransmits(&f).is_err());
        assert_eq!(f.now().0, 1300, "the cap was mutated and left set");
    }
}
