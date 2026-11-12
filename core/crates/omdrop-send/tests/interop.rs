//! Interop on loopback: the `airdrop-send` binary against a real receiver,
//! proving single files, several files, a large file and a link arrive
//! intact.
//!
//! Opt-in, because it runs another implementation:
//! - `OMDROP_INTEROP_PY_SERVE=/path/to/airdrop-serve.py` (needs python3 with
//!   libarchive-c),
//! - `OMDROP_INTEROP_RS_SERVE=/path/to/omdrop-receiver`.
//!
//! Every program gets a temporary HOME, XDG_CONFIG_HOME and XDG_RUNTIME_DIR
//! and its own keys directory, so nothing reads the live identity or config.

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

struct Receiver {
    child: Child,
    port: u16,
    outdir: PathBuf,
    root: tempfile::TempDir,
}

impl Drop for Receiver {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("[::1]:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn private_dirs(root: &Path) {
    use std::os::unix::fs::PermissionsExt;
    for d in ["home", "config", "runtime", "keys", "out"] {
        std::fs::create_dir_all(root.join(d)).unwrap();
    }
    std::fs::set_permissions(root.join("runtime"), std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn isolated(cmd: &mut Command, root: &Path) {
    cmd.env("HOME", root.join("home"))
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("XDG_RUNTIME_DIR", root.join("runtime"))
        .env_remove("OMDROP_DEBUG")
        .env_remove("OMDROP_DEBUG_SENSITIVE")
        .env_remove("PKEXEC_UID")
        .env_remove("SUDO_UID");
}

fn start(argv0: &[&str]) -> Receiver {
    let root = tempfile::tempdir().unwrap();
    private_dirs(root.path());
    let port = free_port();
    let mut cmd = Command::new(argv0[0]);
    cmd.args(&argv0[1..])
        .args(["--iface", "lo", "--port", &port.to_string()])
        .arg("--keys")
        .arg(root.path().join("keys"))
        .arg("--outdir")
        .arg(root.path().join("out"))
        .arg("--config")
        .arg(root.path().join("none.toml"))
        .stdin(Stdio::null())
        .stdout(Stdio::from(
            std::fs::File::create(root.path().join("receiver.log")).unwrap(),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(root.path().join("receiver.err")).unwrap(),
        ));
    isolated(&mut cmd, root.path());
    let child = cmd.spawn().unwrap();
    let addr: SocketAddr = format!("[::1]:{port}").parse().unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut rx = Receiver {
        child,
        port,
        outdir: root.path().join("out"),
        root,
    };
    while TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_err() {
        if Instant::now() > deadline || matches!(rx.child.try_wait(), Ok(Some(_))) {
            let err =
                std::fs::read_to_string(rx.root.path().join("receiver.err")).unwrap_or_default();
            panic!("receiver did not start listening on {addr}: {err}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    rx
}

fn send(rx: &Receiver, args: &[String]) -> Output {
    send_in(rx, args).0
}

/// [`send`], keeping the sender's temporary root (its runtime directory
/// holds any protocol dumps).
fn send_in(rx: &Receiver, args: &[String]) -> (Output, tempfile::TempDir) {
    let root = tempfile::tempdir().unwrap();
    private_dirs(root.path());
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_airdrop-send"));
    cmd.args([
        "--iface",
        "lo",
        "--direct",
        &format!("[::1]:{}", rx.port),
        "--name",
        "Interop Sender",
    ])
    .arg("--keys")
    .arg(root.path().join("keys"))
    .args(args);
    isolated(&mut cmd, root.path());
    let out = cmd.output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let err = String::from_utf8_lossy(&out.stderr);
    let rlog = std::fs::read_to_string(rx.root.path().join("receiver.err")).unwrap_or_default();
    assert!(
        out.status.success(),
        "sender failed ({:?}):\n{text}\n{err}\nreceiver:\n{rlog}",
        out.status
    );
    eprintln!("{text}");
    (out, root)
}

/// Deterministic pseudo-random bytes (xorshift), incompressible.
fn noise(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.truncate(n);
    out
}

fn wait_for(path: &Path, len: usize) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(data) = std::fs::read(path)
            && data.len() == len
        {
            return data;
        }
        assert!(
            Instant::now() < deadline,
            "{} never arrived complete",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn exercise(rx: &Receiver) {
    let src = tempfile::tempdir().unwrap();
    let path = |n: &str| src.path().join(n).to_string_lossy().into_owned();

    // One file.
    std::fs::write(path("hello.txt"), b"hello from omdrop-send\n").unwrap();
    let out = send(rx, &[path("hello.txt")]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("UPLOAD hello.txt -> ok (23 B, "));
    assert_eq!(
        wait_for(&rx.outdir.join("hello.txt"), 23),
        b"hello from omdrop-send\n"
    );

    // Several, one an image (FileIcon), one with spaces, one empty.
    let mut png = Vec::new();
    image::RgbImage::from_pixel(640, 480, image::Rgb([30, 120, 200]))
        .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
        .unwrap();
    std::fs::write(path("photo.png"), &png).unwrap();
    std::fs::write(path("a b c.bin"), noise(100_003, 7)).unwrap();
    std::fs::write(path("empty.dat"), b"").unwrap();
    let out = send(
        rx,
        &[path("photo.png"), path("a b c.bin"), path("empty.dat")],
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("UPLOAD 3 files -> ok ("));
    assert_eq!(wait_for(&rx.outdir.join("photo.png"), png.len()), png);
    assert_eq!(
        wait_for(&rx.outdir.join("a b c.bin"), 100_003),
        noise(100_003, 7)
    );

    // Large: 50 MB, half incompressible (stored DVZip blocks), half zeros.
    let mut big = noise(25 << 20, 99);
    big.resize(50 << 20, 0);
    std::fs::write(path("big.bin"), &big).unwrap();
    let out = send(rx, &[path("big.bin")]);
    let log = String::from_utf8_lossy(&out.stdout);
    assert!(log.contains(&format!("UPLOAD big.bin -> ok ({} B, ", 50 << 20)));
    let steps: Vec<(u64, u64)> = log
        .lines()
        .filter_map(|l| l.split_once("UPLOAD progress ")?.1.split_once('/'))
        .map(|(sent, total)| (sent.parse().unwrap(), total.trim().parse().unwrap()))
        .collect();
    let total = 50u64 << 20;
    assert!(
        steps.first().is_some_and(|&(sent, _)| sent < total),
        "an intermediate step comes before the end: {steps:?}"
    );
    assert_eq!(
        steps.last(),
        Some(&(total, total)),
        "the last step is the whole file"
    );
    assert!(steps.windows(2).all(|w| w[0].0 < w[1].0), "{steps:?}");
    let done = log.find("UPLOAD big.bin -> ok").unwrap();
    assert!(log.rfind("UPLOAD progress ").is_some_and(|at| at < done));
    assert!(
        wait_for(&rx.outdir.join("big.bin"), big.len()) == big,
        "big.bin differs"
    );

    // --verbose: redacted dumps of every exchange in the runtime directory;
    // the upload body only as its size.
    std::fs::write(path("dumped.txt"), b"dump me").unwrap();
    let (_, root) = send_in(rx, &["--verbose".to_owned(), path("dumped.txt")]);
    let dumps = root.path().join("runtime/omdrop/debug");
    for name in [
        "send_discover_request.plist",
        "send_discover_response.plist",
        "send_ask_request.plist",
        "send_ask_response.plist",
        "send_upload_response.plist",
    ] {
        assert!(dumps.join(name).exists(), "{name} missing");
    }
    let upload = std::fs::read_to_string(dumps.join("send_upload_request.plist")).unwrap();
    assert!(
        upload.starts_with("<opaque ") && upload.ends_with(" bytes>"),
        "{upload}"
    );
    let ask = std::fs::read_to_string(dumps.join("send_ask_request.plist")).unwrap();
    assert!(
        ask.contains("dumped.txt") && ask.contains("Interop Sender"),
        "{ask}"
    );

    // A link: the accepted Ask is the transfer.
    let url = "https://example.com/omdrop?interop=1";
    let out = send(rx, &["--url".to_owned(), url.to_owned()]);
    assert!(String::from_utf8_lossy(&out.stdout).contains(&format!("LINK {url} -> ok")));
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("UPLOAD progress "),
        "a link has no upload, so no progress"
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let found = std::fs::read_dir(&rx.outdir)
            .unwrap()
            .filter_map(Result::ok)
            .any(|e| std::fs::read_to_string(e.path()).is_ok_and(|t| t.contains(url)));
        if found {
            break;
        }
        assert!(Instant::now() < deadline, "the link was not stored");
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn against_the_python_receiver() {
    let Some(serve) = std::env::var_os("OMDROP_INTEROP_PY_SERVE") else {
        eprintln!("skipped: set OMDROP_INTEROP_PY_SERVE=/path/to/airdrop-serve.py");
        return;
    };
    let serve = serve.to_string_lossy().into_owned();
    let rx = start(&["python3", &serve]);
    exercise(&rx);
}

#[test]
fn against_the_rust_receiver() {
    let Some(serve) = std::env::var_os("OMDROP_INTEROP_RS_SERVE") else {
        eprintln!("skipped: set OMDROP_INTEROP_RS_SERVE=/path/to/omdrop-receiver");
        return;
    };
    let serve = serve.to_string_lossy().into_owned();
    let rx = start(&[&serve]);
    exercise(&rx);
}
