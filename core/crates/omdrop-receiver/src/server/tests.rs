//! The receiver end to end over TLS on `::1`, in process, with constructed
//! identities and a fake Apple CA.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use omdrop_identity::apple::Record;
use omdrop_identity::{Identity, Source};
use omdrop_proto::archive::{CpioWriter, DvzipEncoder};
use omdrop_proto::contacts::{AppleChecks, hash_identifier};
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};

use super::*;

fn self_signed(cn: &str) -> Identity {
    let dir = tempfile::tempdir().unwrap();
    let ok = std::process::Command::new("openssl")
        .args([
            "req",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-x509",
            "-days",
            "1",
        ])
        .args(["-subj", &format!("/CN={cn}")])
        .arg("-keyout")
        .arg(dir.path().join("key.pem"))
        .arg("-out")
        .arg(dir.path().join("cert.pem"))
        .output()
        .unwrap();
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    Identity {
        source: Source::SelfSigned,
        certificate_pem: std::fs::read(dir.path().join("cert.pem")).unwrap(),
        key_pem: std::fs::read(dir.path().join("key.pem")).unwrap().into(),
        record: None,
        warnings: vec![],
    }
}

/// Apple, as far as these tests are concerned: a record is
/// `SIGNED:<account>|<hash>`, and the one certificate that chains to "Apple"
/// is the test sender's, for account `acct`.
struct FakeApple {
    sender_der: Vec<u8>,
}

impl AppleChecks for FakeApple {
    fn verify_record(&self, record: &[u8]) -> Option<Record> {
        let text = std::str::from_utf8(record).ok()?.strip_prefix("SIGNED:")?;
        let (account, hash) = text.split_once('|')?;
        Some(Record {
            account: account.into(),
            hashes: [hash.to_string()].into(),
            expires: None,
            expired: false,
        })
    }

    fn certificate_account(&self, der: &[u8]) -> String {
        if der == self.sender_der {
            "acct".into()
        } else {
            String::new()
        }
    }
}

struct Fixture {
    port: u16,
    root: tempfile::TempDir,
    sender: Identity,
    server: Arc<Server>,
}

impl Fixture {
    fn dest(&self) -> PathBuf {
        self.root.path().join("out")
    }

    fn files(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(self.dest())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

fn start(contacts_only: bool, tweak: impl FnOnce(&mut Settings)) -> Fixture {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("out")).unwrap();
    let visibility_path = root.path().join("visibility");
    std::fs::write(
        &visibility_path,
        if contacts_only {
            "contacts\n"
        } else {
            "everyone\n"
        },
    )
    .unwrap();
    let known_senders_path = root.path().join("known-senders");
    std::fs::write(&known_senders_path, "friend@example.com\n").unwrap();
    let mut settings = Settings {
        name: "Test Receiver".into(),
        model: "MacBookPro18,3".into(),
        dest: root.path().join("out"),
        max_receive_percent: 30,
        record: Some(b"our record".to_vec()),
        peercert_dir: None,
        visibility_path,
        known_senders_path,
        min_free_bytes: 0,
        limits: ConnLimits::default(),
    };
    tweak(&mut settings);
    let receiver = self_signed("receiver");
    let sender = self_signed("sender");
    let auth = if contacts_only {
        tls::ClientAuth::Request {
            hint_subjects: vec![],
        }
    } else {
        tls::ClientAuth::None
    };
    let config = tls::server_config(&receiver, auth).unwrap();
    let (chain, _) = tls::certified_key(&sender).unwrap();
    let apple = FakeApple {
        sender_der: chain[0].as_ref().to_vec(),
    };
    let server = Arc::new(Server::with_apple(settings, config, Box::new(apple)));
    let listener = TcpListener::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0))).unwrap();
    let port = listener.local_addr().unwrap().port();
    let s = Arc::clone(&server);
    std::thread::spawn(move || s.serve(listener));
    Fixture {
        port,
        root,
        sender,
        server,
    }
}

type Client = BufReader<StreamOwned<ClientConnection, TcpStream>>;

/// A client presenting the sender's certificate, or none at all.
fn connect(fx: &Fixture, with_cert: bool) -> Client {
    let config = if with_cert {
        tls::client_config(&fx.sender).unwrap()
    } else {
        let provider = tls::provider();
        Arc::new(
            rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AnyServer))
                .with_no_client_auth(),
        )
    };
    let sock = TcpStream::connect((Ipv6Addr::LOCALHOST, fx.port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let conn =
        ClientConnection::new(config, ServerName::IpAddress(Ipv6Addr::LOCALHOST.into())).unwrap();
    BufReader::new(StreamOwned::new(conn, sock))
}

#[derive(Debug)]
struct AnyServer;

impl rustls::client::danger::ServerCertVerifier for AnyServer {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        tls::provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Send a request with a chunked body (as sharingd frames /Discover and
/// /Ask), or the given raw body bytes and headers.
fn request(c: &mut Client, path: &str, headers: &[(&str, &str)], body: &[u8], chunked: bool) {
    let mut out = format!("POST {path} HTTP/1.1\r\nHost: x\r\n");
    for (k, v) in headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    if chunked {
        out.push_str("Transfer-Encoding: chunked\r\n\r\n");
        let mut bytes = out.into_bytes();
        for part in body.chunks(1000) {
            bytes.extend(format!("{:x}\r\n", part.len()).bytes());
            bytes.extend(part);
            bytes.extend(b"\r\n");
        }
        bytes.extend(b"0\r\n\r\n");
        c.get_mut().write_all(&bytes).unwrap();
    } else {
        out.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
        let mut bytes = out.into_bytes();
        bytes.extend(body);
        c.get_mut().write_all(&bytes).unwrap();
    }
    c.get_mut().flush().unwrap();
}

/// Status, headers and body of the next final response (skipping 100s).
fn response(c: &mut Client) -> (u16, Vec<(String, String)>, Vec<u8>) {
    loop {
        let mut line = String::new();
        c.read_line(&mut line).unwrap();
        let status: u16 = line
            .split(' ')
            .nth(1)
            .unwrap_or_default()
            .parse()
            .unwrap_or_else(|_| panic!("{line:?}"));
        let mut headers = Vec::new();
        loop {
            let mut h = String::new();
            c.read_line(&mut h).unwrap();
            let h = h.trim_end();
            if h.is_empty() {
                break;
            }
            let (k, v) = h.split_once(':').unwrap();
            headers.push((k.to_lowercase(), v.trim().to_string()));
        }
        if status == 100 {
            continue;
        }
        let length = headers
            .iter()
            .find(|(k, _)| k == "content-length")
            .map(|(_, v)| v.parse().unwrap())
            .unwrap_or(0);
        let mut body = vec![0u8; length];
        c.read_exact(&mut body).unwrap();
        return (status, headers, body);
    }
}

fn post(c: &mut Client, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
    request(c, path, &[], body, true);
    let (status, _, body) = response(c);
    (status, body)
}

fn plist_bytes(dict: Dictionary) -> Vec<u8> {
    binary_plist(dict)
}

fn ask_body(record: Option<&[u8]>) -> Vec<u8> {
    let mut d = Dictionary::new();
    d.insert("SenderComputerName".into(), Value::String("Mac".into()));
    d.insert(
        "TransferType".into(),
        Value::Dictionary(Dictionary::from_iter([(
            "files".to_string(),
            Value::Integer(1.into()),
        )])),
    );
    if let Some(r) = record {
        d.insert("SenderRecordData".into(), Value::Data(r.to_vec()));
    }
    plist_bytes(d)
}

fn dvzip(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = CpioWriter::new(Vec::new());
    for (name, data) in files {
        w.append_raw(name.as_bytes(), 0o100_644, data).unwrap();
    }
    let mut e = DvzipEncoder::new(Vec::new());
    e.write_all(&w.finish().unwrap()).unwrap();
    e.finish().unwrap()
}

fn upload(c: &mut Client, body: &[u8]) -> u16 {
    request(
        c,
        "/Upload",
        &[
            ("Content-Type", "application/x-dvzip"),
            ("TransferID", "T1"),
            ("Expect", "100-continue"),
        ],
        body,
        true,
    );
    response(c).0
}

fn friend_record() -> Vec<u8> {
    format!("SIGNED:acct|{}", hash_identifier("friend@example.com")).into_bytes()
}

#[test]
fn discover_answers_with_name_model_capabilities_and_record() {
    let fx = start(false, |_| {});
    let (status, body) = post(
        &mut connect(&fx, false),
        "/Discover",
        &plist_bytes(Dictionary::new()),
    );
    assert_eq!(status, 200);
    let answer = safeplist::parse_dict(&body).unwrap();
    assert_eq!(
        answer
            .get("ReceiverComputerName")
            .and_then(Value::as_string),
        Some("Test Receiver")
    );
    assert_eq!(
        answer.get("ReceiverModelName").and_then(Value::as_string),
        Some("MacBookPro18,3")
    );
    // An iPhone sends HEIC and HEVC originals only to a receiver whose
    // capabilities are version 3 and declare the HEVC codec; anything less
    // and it converts them to JPEG and H.264 first (R6, 2026-10-14).
    let caps = answer
        .get("ReceiverMediaCapabilities")
        .and_then(Value::as_data)
        .map(String::from_utf8_lossy)
        .unwrap_or_default();
    assert!(caps.contains(r#""Version":3"#), "{caps}");
    assert!(caps.contains(r#""hvc1""#), "{caps}");
    // A Mac's answers carry it (plugin c043688).
    assert_eq!(
        answer.get("IsAirDropable").and_then(Value::as_boolean),
        Some(true)
    );
    assert_eq!(
        answer.get("ReceiverRecordData").and_then(Value::as_data),
        Some(&b"our record"[..])
    );
}

#[test]
fn ask_then_upload_on_one_connection_stores_the_files() {
    let fx = start(false, |_| {});
    let mut c = connect(&fx, false);
    let (status, body) = post(&mut c, "/Ask", &ask_body(None));
    assert_eq!(status, 200);
    let keys: Vec<String> = safeplist::parse_dict(&body)
        .unwrap()
        .keys()
        .cloned()
        .collect();
    assert_eq!(
        keys,
        [
            "ReceiverComputerName",
            "ReceiverMediaCapabilities",
            "ReceiverModelName",
            "IsAirDropable"
        ]
    );
    let big = vec![7u8; 300_000];
    request(
        &mut c,
        "/Upload",
        &[
            ("Content-Type", "application/x-dvzip"),
            ("TransferID", "T1"),
            ("Expect", "100-continue"),
        ],
        &dvzip(&[("./hello.txt", b"hello world\n"), ("./big.bin", &big)]),
        true,
    );
    let (status, headers, _) = response(&mut c);
    assert_eq!(status, 200);
    assert_eq!(fx.files(), ["big.bin", "hello.txt"]);
    assert_eq!(
        std::fs::read(fx.dest().join("hello.txt")).unwrap(),
        b"hello world\n"
    );
    // A finished upload ends the connection at once (plugin #69): an iPhone
    // shows "Sending" until it closes, so the idle limit must not decide.
    assert!(
        headers.contains(&("connection".to_string(), "close".to_string())),
        "{headers:?}"
    );
    let mut rest = Vec::new();
    assert_eq!(c.read_to_end(&mut rest).unwrap(), 0);
    // Content-Length framing works as well as chunked, on a new connection.
    let mut c = connect(&fx, false);
    request(
        &mut c,
        "/Upload",
        &[("Content-Type", "application/x-dvzip")],
        &dvzip(&[("x", b"x")]),
        false,
    );
    assert_eq!(response(&mut c).0, 200);
    assert_eq!(fx.files(), ["big.bin", "hello.txt", "x"]);
}

#[test]
fn an_x_cpio_upload_from_older_ios_is_stored() {
    // iOS 16 labels the same compressed CPIO archive `application/x-cpio`;
    // a 415 made the iPhone report every transfer as failed (plugin #40).
    let fx = start(false, |_| {});
    for (name, body) in [
        ("dvzip.jpg", dvzip(&[("dvzip.jpg", b"jpeg bytes")])),
        ("gzip.jpg", gzip(&cpio_of(&[("gzip.jpg", b"jpeg bytes")]))),
    ] {
        let mut c = connect(&fx, false);
        let (status, _) = post(&mut c, "/Ask", &ask_body(None));
        assert_eq!(status, 200, "{name}");
        request(
            &mut c,
            "/Upload",
            &[
                ("Content-Type", "application/x-cpio"),
                ("TransferID", name),
                ("Expect", "100-continue"),
            ],
            &body,
            true,
        );
        assert_eq!(response(&mut c).0, 200, "{name}");
        assert_eq!(
            std::fs::read(fx.dest().join(name)).unwrap(),
            b"jpeg bytes",
            "{name}"
        );
    }
    assert_eq!(fx.files(), ["dvzip.jpg", "gzip.jpg"]);
}

#[test]
fn hostile_uploads_are_refused_and_leave_nothing() {
    let fx = start(false, |_| {});
    let mut c = connect(&fx, false);
    request(
        &mut c,
        "/Upload",
        &[("Content-Type", "text/plain")],
        b"x",
        false,
    );
    assert_eq!(response(&mut c).0, 415);

    // Garbage: the body is still read to its end so the 422 arrives.
    let mut c = connect(&fx, false);
    let mut garbage = (0x8000_0000u32 | 200_000).to_be_bytes().to_vec();
    garbage.extend(vec![b'z'; 200_000]);
    assert_eq!(upload(&mut c, &garbage), 422);

    // Traversal stays inside the download directory; links are never made.
    let mut w = CpioWriter::new(Vec::new());
    w.append_raw(b"../../escape.txt", 0o100_644, b"1").unwrap();
    w.append_raw(b"./evil-link", 0o120_777, b"/etc/passwd")
        .unwrap();
    w.append_raw(b"/abs/path.txt", 0o100_644, b"2").unwrap();
    let mut e = DvzipEncoder::new(Vec::new());
    e.write_all(&w.finish().unwrap()).unwrap();
    let mut c = connect(&fx, false);
    assert_eq!(upload(&mut c, &e.finish().unwrap()), 200);
    assert_eq!(fx.files(), ["escape.txt", "path.txt"]);
    assert!(!fx.root.path().join("escape.txt").exists());

    // A malformed chunk on /Ask.
    let mut c = connect(&fx, false);
    c.get_mut()
        .write_all(b"POST /Ask HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n")
        .unwrap();
    assert_eq!(response(&mut c).0, 400);

    // A truncated upload: the sender vanishes mid-body.
    let mut c = connect(&fx, false);
    let body = dvzip(&[("partial.bin", &vec![1u8; 100_000])]);
    c.get_mut()
        .write_all(
            format!(
                "POST /Upload HTTP/1.1\r\nContent-Type: application/x-dvzip\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .unwrap();
    c.get_mut().write_all(&body[..body.len() / 2]).unwrap();
    c.get_mut().flush().unwrap();
    c.get_mut().conn.send_close_notify();
    let _ = c.get_mut().flush();
    let _ = c.get_mut().sock.shutdown(Shutdown::Write);
    assert_eq!(response(&mut c).0, 400);
    assert_eq!(fx.files(), ["escape.txt", "path.txt"]);
}

#[test]
fn byte_budget_limits_uploads_before_they_are_read() {
    let fx = start(false, |s| s.min_free_bytes = u64::MAX);
    let mut c = connect(&fx, false);
    assert_eq!(upload(&mut c, &dvzip(&[("a", b"a")])), 413);
    assert_eq!(
        ReceiveBudget::compute(1000, 30, 100).unwrap().byte_limit,
        300
    );
    assert_eq!(
        ReceiveBudget::compute(1000, 90, 300).unwrap().byte_limit,
        700
    );
    assert!(ReceiveBudget::compute(1000, 30, 1000).is_err());
}

#[test]
fn links_are_stored_as_inert_shortcuts() {
    let fx = start(false, |_| {});
    let mut d = Dictionary::new();
    d.insert(
        "TransferType".into(),
        Value::Dictionary(Dictionary::from_iter([(
            "links".to_string(),
            Value::Integer(1.into()),
        )])),
    );
    d.insert(
        "Items".into(),
        Value::Array(vec![
            Value::String("https://example.com/a/page.html?x=1".into()),
            Value::String("file:///etc/passwd".into()),
            Value::String("https://evil.example/\n[InternetShortcut]\nURL=file:///".into()),
            Value::Integer(3.into()),
        ]),
    );
    let (status, _) = post(&mut connect(&fx, false), "/Ask", &plist_bytes(d));
    assert_eq!(status, 200);
    assert_eq!(fx.files(), ["example.com-page.html.url"]);
    assert_eq!(
        std::fs::read_to_string(fx.dest().join("example.com-page.html.url")).unwrap(),
        "[InternetShortcut]\nURL=https://example.com/a/page.html?x=1\n"
    );
    assert_eq!(
        store_link("https://example.com/", &fx.dest()).unwrap(),
        "example.com.url"
    );
    assert_eq!(
        store_link("https://example.com/", &fx.dest()).unwrap(),
        "example.com-1.url"
    );
    let long = format!("https://{}.example/", "h".repeat(400));
    assert!(store_link(&long, &fx.dest()).unwrap().len() <= 255);
}

#[test]
fn an_ask_with_too_many_items_is_refused() {
    let fx = start(false, |_| {});
    let mut d = Dictionary::new();
    d.insert(
        "Items".into(),
        Value::Array(vec![Value::String("x".into()); MAX_ARCHIVE_MEMBERS + 1]),
    );
    assert_eq!(
        post(&mut connect(&fx, false), "/Ask", &plist_bytes(d)).0,
        413
    );
}

#[test]
fn other_requests() {
    let fx = start(false, |_| {});
    let mut c = connect(&fx, false);
    c.get_mut().write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
    let (status, _, body) = response(&mut c);
    assert_eq!((status, body.as_slice()), (200, &b"\n"[..]));
    request(&mut c, "/Nope", &[], b"", false);
    assert_eq!(response(&mut c).0, 400);
    let mut c = connect(&fx, false);
    c.get_mut().write_all(b"PUT / HTTP/1.1\r\n\r\n").unwrap();
    assert_eq!(response(&mut c).0, 501);
}

#[test]
fn contacts_only_gates_discovery_ask_and_upload() {
    let fx = start(true, |_| {});
    // Upload with no accepted Ask on this session.
    let mut c = connect(&fx, true);
    assert_eq!(upload(&mut c, &dvzip(&[("a", b"a")])), 403);

    // A stranger's valid record: hidden at Discover, refused at Ask.
    let stranger = format!("SIGNED:acct|{}", hash_identifier("stranger@example.com")).into_bytes();
    let mut d = Dictionary::new();
    d.insert("SenderRecordData".into(), Value::Data(stranger.clone()));
    assert_eq!(
        post(&mut connect(&fx, true), "/Discover", &plist_bytes(d)).0,
        401
    );
    assert_eq!(
        post(&mut connect(&fx, true), "/Ask", &ask_body(Some(&stranger))).0,
        403
    );

    // An unidentifiable sender still sees us (fails open), but cannot send.
    assert_eq!(
        post(
            &mut connect(&fx, false),
            "/Discover",
            &plist_bytes(Dictionary::new())
        )
        .0,
        200
    );
    assert_eq!(
        post(
            &mut connect(&fx, false),
            "/Ask",
            &ask_body(Some(&friend_record()))
        )
        .0,
        403
    );

    // A friend with the matching certificate: Ask, then Upload on the session.
    let mut c = connect(&fx, true);
    assert_eq!(
        post(&mut c, "/Ask", &ask_body(Some(&friend_record()))).0,
        200
    );
    assert_eq!(upload(&mut c, &dvzip(&[("from-friend.txt", b"hi")])), 200);
    assert_eq!(fx.files(), ["from-friend.txt"]);
    // A new session needs its own Ask.
    assert_eq!(upload(&mut connect(&fx, true), &dvzip(&[("b", b"b")])), 403);
}

#[test]
fn stopping_resets_live_sessions() {
    let fx = start(false, |_| {});
    let mut c = connect(&fx, false);
    assert_eq!(
        post(&mut c, "/Discover", &plist_bytes(Dictionary::new())).0,
        200
    );
    // The server thread registered the session; reset it and drop the
    // server's own handle, as the exiting process does.
    std::thread::sleep(Duration::from_millis(100));
    let live_count = || fx.server.live.lock().map(|l| l.len()).unwrap_or(usize::MAX);
    assert_eq!(live_count(), 1);
    let socks: Vec<TcpStream> = fx
        .server
        .live
        .lock()
        .map(|l| l.values().map(|s| s.sock.try_clone().unwrap()).collect())
        .unwrap_or_default();
    fx.server.reset_sessions();
    assert_eq!(live_count(), 0);
    for s in socks {
        // Shutting down both halves of the server's socket, with linger 0,
        // is what process exit does to it.
        let _ = s.shutdown(Shutdown::Both);
    }
    let mut buf = [0u8; 1];
    match c.get_mut().sock.read(&mut buf) {
        Ok(0) | Err(_) => {}
        Ok(n) => panic!("read {n} bytes from a reset session"),
    }
}

/// Whether the server has closed this raw connection, within `within`.
fn closed_by_server(sock: &mut TcpStream, within: Duration) -> bool {
    sock.set_read_timeout(Some(within)).unwrap();
    let mut buf = [0u8; 1024];
    loop {
        match sock.read(&mut buf) {
            Ok(0) => return true,
            Ok(_) => continue,
            Err(e) if http::is_timeout(&e) => return false,
            Err(_) => return true,
        }
    }
}

fn raw(fx: &Fixture) -> TcpStream {
    let sock = TcpStream::connect((Ipv6Addr::LOCALHOST, fx.port)).unwrap();
    // Let the accept loop register it before the next one arrives.
    std::thread::sleep(Duration::from_millis(50));
    sock
}

#[test]
fn one_peer_cannot_hold_more_than_its_share_of_connections() {
    let fx = start(false, |s| s.limits.max_per_peer = 2);
    let first = raw(&fx);
    let mut second = raw(&fx);
    let mut third = raw(&fx);
    assert!(closed_by_server(&mut third, Duration::from_secs(5)));
    assert!(!closed_by_server(&mut second, Duration::from_millis(200)));
    drop(first);
    std::thread::sleep(Duration::from_millis(200));
    let (status, _) = post(
        &mut connect(&fx, false),
        "/Discover",
        &plist_bytes(Dictionary::new()),
    );
    assert_eq!(status, 200);
}

#[test]
fn silent_connections_make_room_for_a_real_sender() {
    let fx = start(false, |s| {
        s.limits.max_connections = 2;
        s.limits.max_per_peer = 64;
    });
    let mut oldest = raw(&fx);
    let mut newer = raw(&fx);
    let (status, _) = post(
        &mut connect(&fx, false),
        "/Discover",
        &plist_bytes(Dictionary::new()),
    );
    assert_eq!(status, 200);
    assert!(closed_by_server(&mut oldest, Duration::from_secs(5)));
    assert!(!closed_by_server(&mut newer, Duration::from_millis(200)));
}

#[test]
fn a_trickled_handshake_is_cut_off_at_the_deadline() {
    let fx = start(false, |s| s.limits.head_deadline = Duration::from_secs(1));
    let mut sock = raw(&fx);
    let started = std::time::Instant::now();
    // A ClientHello's first bytes, one every 200 ms: each read is well inside
    // the idle timeout, the whole is not inside the deadline.
    let hello = [
        0x16u8, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03,
    ];
    let mut closed = false;
    for byte in hello.iter().cycle().take(40) {
        if sock.write_all(&[*byte]).is_err()
            || closed_by_server(&mut sock, Duration::from_millis(200))
        {
            closed = true;
            break;
        }
    }
    assert!(closed, "still open after {:?}", started.elapsed());
    let took = started.elapsed();
    assert!(
        took >= Duration::from_millis(800) && took < Duration::from_secs(4),
        "{took:?}"
    );
}

#[test]
fn a_trickled_request_head_is_cut_off_at_the_deadline() {
    let fx = start(false, |s| s.limits.head_deadline = Duration::from_secs(1));
    let mut c = connect(&fx, false);
    // A first request, so the deadline is shown to restart per request.
    assert_eq!(
        post(&mut c, "/Discover", &plist_bytes(Dictionary::new())).0,
        200
    );
    std::thread::sleep(Duration::from_millis(600));
    c.get_mut()
        .write_all(b"POST /Discover HTTP/1.1\r\n")
        .unwrap();
    c.get_mut().flush().unwrap();
    let started = std::time::Instant::now();
    c.get_mut()
        .sock
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut closed = false;
    for _ in 0..20 {
        let _ = c
            .get_mut()
            .write_all(b"X-Slow: y\r\n")
            .and_then(|()| c.get_mut().flush());
        let mut buf = [0u8; 64];
        match c.get_mut().read(&mut buf) {
            Err(e) if http::is_timeout(&e) => continue,
            _ => {
                closed = true;
                break;
            }
        }
    }
    assert!(closed, "still open after {:?}", started.elapsed());
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn log_labels_leave_no_room_for_forgery() {
    assert_eq!(
        transfer_label("D20AAC9E-5242-4C35-8789-11CEE78F9D68"),
        "D20AAC9E-5242-4C35-8789-11CEE78F9D68"
    );
    assert_eq!(transfer_label("x: stored /etc/passwd"), "xstoredetcpasswd");
    assert_eq!(transfer_label("..."), "upload");
    assert_eq!(transfer_label(&"a".repeat(100)).len(), 64);
    let names: Vec<String> = (0..512)
        .map(|i| format!("{i:03}{}", "n".repeat(250)))
        .collect();
    let lines = stored_lines(&names);
    assert!(lines.len() > 1);
    assert!(lines.iter().all(|l| l.len() <= MAX_STORED_LINE_BYTES));
    let rejoined: Vec<String> = lines
        .iter()
        .flat_map(|l| l.split(", ").map(str::to_string))
        .collect();
    assert_eq!(rejoined, names);
    assert_eq!(
        stored_lines(&["a.txt".into(), "b.txt".into()]),
        ["a.txt, b.txt"]
    );
}

#[test]
fn links_with_spaces_are_not_stored() {
    let fx = start(false, |_| {});
    let mut d = Dictionary::new();
    d.insert(
        "TransferType".into(),
        Value::Dictionary(Dictionary::from_iter([(
            "links".to_string(),
            Value::Integer(1.into()),
        )])),
    );
    d.insert(
        "Items".into(),
        Value::Array(vec![Value::String(
            "https://a -> b.example/ INFO root: upload x: stored y".into(),
        )]),
    );
    assert_eq!(
        post(&mut connect(&fx, false), "/Ask", &plist_bytes(d)).0,
        200
    );
    assert!(fx.files().is_empty());
}

fn links_ask(urls: &[&str]) -> Vec<u8> {
    let mut d = Dictionary::new();
    d.insert(
        "TransferType".into(),
        Value::Dictionary(Dictionary::from_iter([(
            "links".to_string(),
            Value::Integer(1.into()),
        )])),
    );
    d.insert(
        "Items".into(),
        Value::Array(urls.iter().map(|u| Value::String((*u).into())).collect()),
    );
    plist_bytes(d)
}

/// A links Ask is the whole transfer, so it gets an upload's budget: 512
/// links a time, any number of times, must not fill the disk past
/// MIN_FREE_BYTES.
#[test]
fn links_past_the_receive_budget_are_refused_and_none_stored() {
    let ask = links_ask(&["https://example.com/a", "https://example.com/b"]);
    for tweak in [
        (|s: &mut Settings| s.min_free_bytes = u64::MAX) as fn(&mut Settings),
        |s| s.max_receive_percent = 0,
    ] {
        let fx = start(false, tweak);
        assert_eq!(post(&mut connect(&fx, false), "/Ask", &ask).0, 507);
        assert!(fx.files().is_empty());
    }
    // Within budget, all are stored.
    let fx = start(false, |_| {});
    assert_eq!(post(&mut connect(&fx, false), "/Ask", &ask).0, 200);
    assert_eq!(fx.files(), ["example.com-a.url", "example.com-b.url"]);
    // Each costs its file and a block.
    let url = "https://example.com/";
    assert_eq!(
        links_cost(&[url, url]),
        2 * ("[InternetShortcut]\nURL=\n".len() + url.len() + 4096) as u64
    );
}

#[test]
fn links_longer_than_8192_bytes_are_not_stored() {
    let fx = start(false, |_| {});
    let base = "https://example.com/";
    let longest = format!("{base}{}", "a".repeat(MAX_LINK_URL_BYTES - base.len()));
    let over = format!("{longest}b");
    let ask = links_ask(&[&over, &longest]);
    assert_eq!(post(&mut connect(&fx, false), "/Ask", &ask).0, 200);
    let files = fx.files();
    assert_eq!(files.len(), 1, "{files:?}");
    assert_eq!(
        std::fs::read_to_string(fx.dest().join(&files[0])).unwrap(),
        format!("[InternetShortcut]\nURL={longest}\n")
    );
}

#[test]
fn peer_certificates_are_captured_when_asked() {
    let capture = tempfile::tempdir().unwrap();
    let dir = capture.path().to_path_buf();
    let fx = start(true, |s| s.peercert_dir = Some(dir));
    assert_eq!(
        post(
            &mut connect(&fx, true),
            "/Discover",
            &plist_bytes(Dictionary::new())
        )
        .0,
        200
    );
    let mut names: Vec<String> = std::fs::read_dir(capture.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names.len(), 2, "{names:?}");
    assert!(
        names[0].starts_with("client-") && names[0].ends_with("Z-depth0.der"),
        "{names:?}"
    );
    assert!(names[1].ends_with("Z.der"), "{names:?}");
}

/// Limits short enough to test the waits: a 300 ms boundary step, 2 s of
/// silence before a 408, a drain that stops after 300 ms of quiet.
fn patient_limits(s: &mut Settings) {
    s.limits.upload_step = Duration::from_millis(300);
    s.limits.idle_timeout = Duration::from_secs(2);
    s.limits.drain_quiet = Duration::from_millis(300);
    s.limits.drain_limit = Duration::from_secs(2);
}

/// An Upload whose chunked body is sent whole, but without its closing `0`
/// chunk, as an iPhone sometimes does (plugin #41).
fn upload_without_closing_chunk(c: &mut Client, body: &[u8]) {
    let mut bytes = b"POST /Upload HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-dvzip\r\nTransferID: T1\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    for part in body.chunks(1000) {
        bytes.extend(format!("{:x}\r\n", part.len()).bytes());
        bytes.extend(part);
        bytes.extend(b"\r\n");
    }
    c.get_mut().write_all(&bytes).unwrap();
    c.get_mut().flush().unwrap();
}

/// What the client reads after the answer: `Ok(0)` for the receiver's clean
/// close (TLS close_notify), an error for a reset.
fn after_answer(c: &mut Client) -> io::Result<usize> {
    c.get_mut()
        .get_mut()
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut rest = Vec::new();
    c.read_to_end(&mut rest)
}

#[test]
fn a_whole_archive_without_its_closing_chunk_is_stored_and_answered() {
    let fx = start(false, patient_limits);
    let mut c = connect(&fx, false);
    let started = std::time::Instant::now();
    upload_without_closing_chunk(&mut c, &dvzip(&[("clip.mov", &vec![5u8; 50_000])]));
    let (status, _, _) = response(&mut c);
    assert_eq!(status, 200);
    // Answered after one quiet step, not after the 2 s idle limit.
    assert!(
        started.elapsed() < Duration::from_millis(1500),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(fx.files(), ["clip.mov"]);
    // The sender sends nothing more: the drain ends on its quiet time and the
    // receiver closes cleanly.
    let closed = std::time::Instant::now();
    assert!(matches!(after_answer(&mut c), Ok(0)), "not a clean close");
    assert!(
        closed.elapsed() < Duration::from_secs(2),
        "{:?}",
        closed.elapsed()
    );
}

#[test]
fn a_closing_chunk_sent_after_the_early_answer_is_drained_not_reset() {
    // A Mac's sharingd sends the closing chunk only once it has the answer;
    // closing with it unread makes a reset, and the Mac reports a failure.
    let fx = start(false, patient_limits);
    let mut c = connect(&fx, false);
    upload_without_closing_chunk(&mut c, &dvzip(&[("late.bin", b"late")]));
    assert_eq!(response(&mut c).0, 200);
    c.get_mut().write_all(b"0\r\n\r\n").unwrap();
    c.get_mut().flush().unwrap();
    assert!(matches!(after_answer(&mut c), Ok(0)), "not a clean close");
    assert_eq!(fx.files(), ["late.bin"]);
}

#[test]
fn half_an_archive_without_its_closing_chunk_still_times_out() {
    let fx = start(false, patient_limits);
    let mut c = connect(&fx, false);
    let whole = dvzip(&[("half.bin", &vec![9u8; 50_000])]);
    let started = std::time::Instant::now();
    upload_without_closing_chunk(&mut c, &whole[..whole.len() / 2]);
    assert_eq!(response(&mut c).0, 408);
    assert!(
        started.elapsed() >= Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(fx.files(), Vec::<String>::new());
}

#[test]
fn an_archive_cut_between_members_is_not_taken_for_whole() {
    // A cpio archive cut cleanly before its second member decodes without
    // error but has no TRAILER!!!: the files that never came must not be
    // silently dropped by storing the first alone.
    let fx = start(false, patient_limits);
    let mut w = CpioWriter::new(Vec::new());
    w.append_raw(b"first.bin", 0o100_644, &[1u8; 3000]).unwrap();
    w.append_raw(b"second.bin", 0o100_644, &[2u8; 3000])
        .unwrap();
    let cpio = w.finish().unwrap();
    let second = cpio
        .windows(6)
        .enumerate()
        .filter(|(_, w)| *w == b"070707")
        .nth(1)
        .map(|(i, _)| i)
        .unwrap();
    let mut e = DvzipEncoder::new(Vec::new());
    e.write_all(&cpio[..second]).unwrap();
    let mut c = connect(&fx, false);
    upload_without_closing_chunk(&mut c, &e.finish().unwrap());
    assert_eq!(response(&mut c).0, 408);
    assert_eq!(fx.files(), Vec::<String>::new());
}

fn cpio_of(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = CpioWriter::new(Vec::new());
    for (name, data) in files {
        w.append_raw(name.as_bytes(), 0o100_644, data).unwrap();
    }
    w.finish().unwrap()
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// A quiet body past `TRAILER!!!` must also be at the end of its compressed
/// stream to be whole; otherwise it waits out the idle limit, as plugin main
/// does (its completeness check decodes the stream and refuses truncation).
fn assert_not_whole(body: &[u8]) {
    let fx = start(false, patient_limits);
    let mut c = connect(&fx, false);
    let started = std::time::Instant::now();
    upload_without_closing_chunk(&mut c, body);
    assert_eq!(response(&mut c).0, 408);
    assert!(
        started.elapsed() >= Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(fx.files(), Vec::<String>::new());
}

#[test]
fn a_whole_gzip_archive_without_its_closing_chunk_is_stored() {
    let fx = start(false, patient_limits);
    let mut c = connect(&fx, false);
    let started = std::time::Instant::now();
    upload_without_closing_chunk(&mut c, &gzip(&cpio_of(&[("clip.mov", &[7u8; 50_000])])));
    assert_eq!(response(&mut c).0, 200);
    assert!(
        started.elapsed() < Duration::from_millis(1500),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(fx.files(), ["clip.mov"]);
}

#[test]
fn a_gzip_body_quiet_inside_its_footer_is_not_whole() {
    // Every file and the trailer decoded, but the CRC and length never came.
    let body = gzip(&cpio_of(&[("clip.mov", &[7u8; 50_000])]));
    assert_not_whole(&body[..body.len() - 8]);
}

#[test]
fn a_dvzip_body_quiet_inside_its_last_block_is_not_whole() {
    // One stored block that announces 100 bytes more than are sent: the
    // trailer is inside what arrived, the block's end is not.
    let cpio = cpio_of(&[("clip.mov", &[7u8; 50_000])]);
    let declared = u32::try_from(cpio.len() + 100).unwrap() | omdrop_proto::archive::DVZIP_STORED;
    let mut body = declared.to_be_bytes().to_vec();
    body.extend(&cpio);
    assert_not_whole(&body);
}

#[test]
fn a_dvzip_body_quiet_inside_a_further_block_header_is_not_whole() {
    // A whole archive, then two bytes of a next block's header (hume's probe,
    // 2026-10-14): the body stopped inside its framing, not between blocks.
    let mut body = dvzip(&[("clip.mov", &[7u8; 50_000])]);
    body.extend([0x80, 0x00]);
    assert_not_whole(&body);
}

#[test]
fn an_upload_may_start_later_than_the_idle_limit_after_an_accepted_ask() {
    // A poor AWDL link can delay the Upload after the Ask (plugin a800d74).
    let fx = start(false, |s| {
        s.limits.idle_timeout = Duration::from_secs(1);
        s.limits.upload_wait = Duration::from_secs(4);
    });
    let mut c = connect(&fx, false);
    assert_eq!(post(&mut c, "/Ask", &ask_body(None)).0, 200);
    std::thread::sleep(Duration::from_millis(2500));
    assert_eq!(upload(&mut c, &dvzip(&[("slow.bin", b"slow")])), 200);
    assert_eq!(fx.files(), ["slow.bin"]);
}

#[test]
fn upload_slots_are_capped_and_freed_on_drop() {
    let counter = AtomicUsize::new(0);
    let a = try_slot(&counter, 2).expect("first slot");
    let b = try_slot(&counter, 2).expect("second slot");
    assert!(try_slot(&counter, 2).is_none(), "a third upload must wait");
    drop(a);
    let c = try_slot(&counter, 2).expect("a freed slot is reusable");
    drop((b, c));
    assert_eq!(counter.load(Ordering::SeqCst), 0);
}

#[test]
fn racing_threads_never_hold_more_slots_than_the_cap() {
    let counter = AtomicUsize::new(0);
    let peak = AtomicUsize::new(0);
    std::thread::scope(|s| {
        for _ in 0..8 {
            s.spawn(|| {
                for _ in 0..2000 {
                    if let Some(slot) = try_slot(&counter, 2) {
                        peak.fetch_max(counter.load(Ordering::SeqCst), Ordering::SeqCst);
                        drop(slot);
                    }
                }
            });
        }
    });
    assert!(
        peak.load(Ordering::SeqCst) <= 2,
        "peak {}",
        peak.load(Ordering::SeqCst)
    );
    assert_eq!(counter.load(Ordering::SeqCst), 0);
}

/// Send a request head and part of its body, then end the TCP stream without
/// TLS's close_notify, as a sender does when it cancels or walks out of range.
/// The receiver reads an unclean end; this side keeps reading, to see whether
/// anything is answered. Returns what arrived.
fn leave_mid_request(
    c: &mut Client,
    path: &str,
    content_type: &str,
    partial: &[u8],
    chunked: bool,
) -> Vec<u8> {
    let mut out = format!("POST {path} HTTP/1.1\r\nHost: x\r\nContent-Type: {content_type}\r\n");
    if chunked {
        out.push_str("Transfer-Encoding: chunked\r\n\r\n3e8\r\n");
    } else {
        out.push_str("Content-Length: 1000\r\n\r\n");
    }
    let mut bytes = out.into_bytes();
    bytes.extend(partial);
    c.get_mut().write_all(&bytes).unwrap();
    c.get_mut().flush().unwrap();
    let sock = c.get_mut().get_mut();
    sock.shutdown(std::net::Shutdown::Write).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut answer = Vec::new();
    // The receiver's clean close ends this with Ok, a reset with an error;
    // either way, only what arrived before it matters. A timeout means the
    // receiver kept the connection open, which a departed sender must not
    // cost it.
    if let Err(e) = c.read_to_end(&mut answer) {
        assert!(
            !omdrop_proto::http::is_timeout(&e),
            "the receiver kept the connection open: {e}"
        );
    }
    answer
}

#[test]
fn a_sender_that_leaves_mid_upload_gets_no_answer_and_frees_its_slot() {
    let fx = start(false, |_| {});
    // The start of a real archive, so the decoder is still waiting for the
    // rest when the sender leaves.
    let archive = dvzip(&[("big.bin", &vec![5u8; 200_000])]);
    // More departures than there are upload slots: each must give its back.
    for chunked in [false, true, false, true] {
        let mut c = connect(&fx, false);
        let answer = leave_mid_request(
            &mut c,
            "/Upload",
            "application/x-dvzip",
            &archive[..300],
            chunked,
        );
        // Not "507 storage failed": the disk is fine, and the sender has gone.
        assert_eq!(String::from_utf8_lossy(&answer), "", "chunked={chunked}");
    }
    assert!(fx.files().is_empty(), "{:?}", fx.files());
    let mut c = connect(&fx, false);
    request(
        &mut c,
        "/Upload",
        &[("Content-Type", "application/x-dvzip")],
        &dvzip(&[("after.txt", b"after")]),
        true,
    );
    assert_eq!(response(&mut c).0, 200);
    assert_eq!(fx.files(), ["after.txt"]);
}

#[test]
fn a_sender_that_leaves_mid_ask_gets_no_answer() {
    let fx = start(false, |_| {});
    for chunked in [false, true] {
        let mut c = connect(&fx, false);
        let answer = leave_mid_request(
            &mut c,
            "/Ask",
            "application/octet-stream",
            &ask_body(None)[..20],
            chunked,
        );
        // Not "400 request body read failed": nothing was wrong with it.
        assert_eq!(String::from_utf8_lossy(&answer), "", "chunked={chunked}");
    }
    let mut c = connect(&fx, false);
    assert_eq!(post(&mut c, "/Ask", &ask_body(None)).0, 200);
}
