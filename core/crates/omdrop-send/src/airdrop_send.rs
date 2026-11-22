//! `airdrop-send`: send files or links to one AirDrop receiver (drop-in for
//! omdrop-awdl's `userspace/airdrop-send.py`).
//!
//! Pick a receiver (`--direct HOST:PORT`, the newest endpoint in an
//! `--af-log`, or by browsing `_airdrop._tcp` on the interface), /Discover it,
//! then /Ask and /Upload on a fresh connection. Several files go as one
//! transfer: one /Ask listing them all, so the receiver answers a single
//! prompt, and one /Upload archive holding them all. The receiver must be
//! receiving (a Mac with Finder > AirDrop open, or woken over BLE); it answers
//! /Discover only then, and /Ask blocks until its user accepts.
//!
//! Exit: 0 sent | 2 no receiver found in --timeout | 3 declined | 4 upload
//! failed | 1 identity or interface error | 2 usage error. Every step is
//! timestamped to stdout; `omdrop`'s narrate_send reads the `send` lines.

use std::net::{IpAddr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use omdrop_identity::{Identity, IdentityError, ResolveOptions};

use crate::aflog::endpoints_from_af_log;
use crate::args::{self, Exit, Kind, Opt, Parsed, Spec};
use crate::client::{Client, Outgoing, Sender, basename};
use crate::error::PyErr;
use crate::http::Endpoint;
use crate::log::{Logger, Sink};
use crate::mdns::Browser;
use crate::pyfmt::{list_repr, opt_str_repr, str_repr};

/// Bit 0x80 of a receiver's `flags` TXT value: it answers /Discover.
pub const SUPPORTS_DISCOVER: i64 = 0x80;
/// How long to wait before the one retry of a /Discover whose connection the
/// peer dropped: its AirDrop server is back within milliseconds (R7d).
const DISCOVER_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(500);

static OPTS: &[Opt] = &[
    Opt {
        long: "--url",
        short: None,
        kind: Kind::Append,
    },
    Opt {
        long: "--iface",
        short: None,
        kind: Kind::Value,
    },
    Opt {
        long: "--discover-only",
        short: None,
        kind: Kind::Flag,
    },
    Opt {
        long: "--to",
        short: None,
        kind: Kind::Value,
    },
    Opt {
        long: "--timeout",
        short: None,
        kind: Kind::Value,
    },
    Opt {
        long: "--ask-timeout",
        short: None,
        kind: Kind::Value,
    },
    Opt {
        long: "--op-timeout",
        short: None,
        kind: Kind::Value,
    },
    Opt {
        long: "--af-attempts",
        short: None,
        kind: Kind::Value,
    },
    Opt {
        long: "--auth-tag",
        short: None,
        kind: Kind::Value,
    },
    Opt {
        long: "--should-convert",
        short: None,
        kind: Kind::Flag,
    },
    Opt {
        long: "--direct",
        short: None,
        kind: Kind::Value,
    },
    Opt {
        long: "--af-log",
        short: None,
        kind: Kind::Value,
    },
    Opt {
        long: "--name",
        short: None,
        kind: Kind::Value,
    },
    Opt {
        long: "--model",
        short: None,
        kind: Kind::Value,
    },
    Opt {
        long: "--host",
        short: None,
        kind: Kind::Value,
    },
    Opt {
        long: "--verbose",
        short: None,
        kind: Kind::Flag,
    },
    Opt {
        long: "--keys",
        short: None,
        kind: Kind::Value,
    },
];

pub static SPEC: Spec = Spec {
    prog: "airdrop-send",
    usage: "usage: airdrop-send [-h] [--url URL] [--iface IFACE] [--discover-only]
                    [--to TO] [--timeout TIMEOUT]
                    [--ask-timeout ASK_TIMEOUT] [--op-timeout OP_TIMEOUT]
                    [--af-attempts N] [--auth-tag AUTH_TAG]
                    [--should-convert] [--direct HOST:PORT]
                    [--af-log AF_LOG] [--name NAME] [--model MODEL]
                    [--host HOST] [--verbose] [--keys KEYS]
                    [file ...]",
    help_body: "positional arguments:
  file                  files to send, as one transfer the receiver accepts
                        once

options:
  -h, --help            show this help message and exit
  --url URL             send this http(s) link instead of files; the receiver
                        opens it in its browser
  --iface IFACE
  --discover-only       ask the peer for its name over /Discover, print it,
                        and send nothing
  --to TO               receiver: substring of its name, or 12-hex id
  --timeout TIMEOUT     seconds to wait for a receiver
  --ask-timeout ASK_TIMEOUT
                        seconds for the Mac user to accept
  --op-timeout OP_TIMEOUT
                        seconds any single Discover/Upload socket operation
                        may block; guards against a wedged AWDL TX path
                        parking the client in TCP backoff
  --af-attempts N       independent Discover attempts against the freshest
                        matching af.log endpoint, re-read before each; stops
                        on the first success. Total time is bounded by N*(op-
                        timeout+2)
  --auth-tag AUTH_TAG   3 bytes hex: SenderIdentityAuthTag for the Ask (the
                        bytes our BLE advert carries)
  --should-convert      set Files[].ShouldConvertMediaFormats (a real sender's
                        key; off = one variable held)
  --direct HOST:PORT    skip discovery; Discover/Ask/Upload this endpoint
                        (e.g. \"[::1]:8771\" against a local airdrop-serve)
  --af-log AF_LOG       awdl-af-listen output; take the receiver from the
                        newest AirDrop Service Response TLVs in it (address =
                        EUI-64 link-local of the frame source) before browsing
                        mDNS
  --name NAME           SenderComputerName shown in the Mac dialog
  --model MODEL         SenderModelName
  --host HOST           unused by the sender
  --verbose             write redacted protocol dumps to the user runtime
                        directory
  --keys KEYS           identity directory (default: invoking user's passwd
                        home/.omdrop); replaces the disk and self-signed keys
                        location only
",
    opts: OPTS,
};

/// Everything the command line asked for, validated.
#[derive(Debug)]
pub struct Options {
    pub files: Vec<Outgoing>,
    pub urls: Vec<String>,
    pub iface: String,
    pub discover_only: bool,
    pub to: Option<String>,
    pub timeout: f64,
    pub ask_timeout: Option<Duration>,
    pub op_timeout: Option<Duration>,
    pub op_timeout_secs: f64,
    pub af_attempts: i64,
    pub auth_tag: Option<Vec<u8>>,
    pub should_convert: bool,
    pub direct: Option<String>,
    pub af_log: Option<PathBuf>,
    pub name: String,
    pub model: String,
    pub verbose: bool,
    pub keys: Option<PathBuf>,
    /// Cap the Upload socket's retransmission timeout (#79): `OMDROP_UPLOAD_RTO_CAP`.
    pub upload_rto_cap: bool,
}

/// `OMDROP_UPLOAD_RTO_CAP`'s value when it is unset or empty.
const UPLOAD_RTO_CAP_DEFAULT: bool = false;

/// `OMDROP_UPLOAD_RTO_CAP`: `1` turns the Upload's retransmission cap on, `0` off.
fn upload_rto_cap(v: Option<&str>) -> Result<bool, String> {
    match v {
        None | Some("") => Ok(UPLOAD_RTO_CAP_DEFAULT),
        Some("1") => Ok(true),
        Some("0") => Ok(false),
        Some(other) => Err(format!(
            "OMDROP_UPLOAD_RTO_CAP must be 0 or 1, not {}",
            str_repr(other)
        )),
    }
}

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    // bytes.fromhex: whitespace between bytes is allowed.
    let digits: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    (0..digits.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(digits.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Parse and validate the command line, with airdrop-send.py's messages.
pub fn parse_options(argv: &[String]) -> Result<Options, Exit> {
    let p: Parsed = SPEC.parse(argv)?;
    let op_timeout_secs = SPEC.float(&p, "--op-timeout", 20.0)?;
    let ask_secs = SPEC.float(&p, "--ask-timeout", 90.0)?;
    let timeout = SPEC.float(&p, "--timeout", 60.0)?;
    if !timeout.is_finite() || timeout < 0.0 {
        return Err(SPEC.error("argument --timeout: must be a non-negative number of seconds"));
    }
    let urls = p.all("--url");
    let discover_only = p.flag("--discover-only");
    let direct = p.value("--direct").map(str::to_owned);
    if !discover_only && p.positionals.is_empty() && urls.is_empty() {
        return Err(SPEC.error("a file or --url is required unless --discover-only"));
    }
    if !urls.is_empty() && !p.positionals.is_empty() {
        return Err(
            SPEC.error("send links and files separately: a transfer carries one or the other")
        );
    }
    for u in &urls {
        let lower = u.to_lowercase();
        if !(lower.starts_with("http://") || lower.starts_with("https://"))
            || u.chars().any(char::is_whitespace)
        {
            return Err(SPEC.error(&format!(
                "--url {}: only an http or https link with no spaces",
                str_repr(u)
            )));
        }
    }
    // The archive stores each file under its bare name, as sharingd does, so
    // two files with one name would land as one, and which survived would be luck.
    let names: Vec<String> = p
        .positionals
        .iter()
        .map(|f| basename(Path::new(f)))
        .collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.len() != names.len() {
        return Err(
            SPEC.error("two of the files have the same name; the receiver would keep only one")
        );
    }
    if discover_only && direct.is_none() {
        return Err(SPEC.error("--discover-only needs --direct HOST:PORT, the peer to ask"));
    }
    let auth_tag = match p.value("--auth-tag") {
        None => None,
        Some(t) => Some(hex_bytes(t).ok_or_else(|| {
            SPEC.error(&format!(
                "argument --auth-tag: invalid hex: {}",
                str_repr(t)
            ))
        })?),
    };
    // Checked before anything is woken or dialled: Python found a missing
    // file only at the Ask, after discovery.
    let mut files = Vec::new();
    for f in &p.positionals {
        let out = Outgoing::new(Path::new(f))
            .map_err(|e| SPEC.error(&format!("{f}: {}", strip_os_error(&e))))?;
        files.push(out);
    }
    let upload_rto_cap = match std::env::var("OMDROP_UPLOAD_RTO_CAP") {
        Ok(v) => upload_rto_cap(Some(&v)),
        Err(std::env::VarError::NotPresent) => upload_rto_cap(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err("OMDROP_UPLOAD_RTO_CAP must be 0 or 1, not a non-UTF-8 value".to_owned())
        }
    }
    .map_err(|e| SPEC.error(&e))?;
    Ok(Options {
        files,
        urls,
        iface: p.value("--iface").unwrap_or("awdl0").to_owned(),
        discover_only,
        to: p.value("--to").map(str::to_owned),
        timeout,
        ask_timeout: args::timeout(&SPEC, "--ask-timeout", ask_secs)?,
        op_timeout: args::timeout(&SPEC, "--op-timeout", op_timeout_secs)?,
        op_timeout_secs,
        af_attempts: SPEC.int(&p, "--af-attempts", 1)?,
        auth_tag,
        should_convert: p.flag("--should-convert"),
        direct,
        af_log: p.value("--af-log").map(PathBuf::from),
        name: p.value("--name").unwrap_or("f0010").to_owned(),
        model: p.value("--model").unwrap_or("MacBookPro18,3").to_owned(),
        verbose: p.flag("--verbose"),
        keys: p.value("--keys").map(PathBuf::from),
        upload_rto_cap,
    })
}

fn strip_os_error(e: &std::io::Error) -> String {
    let s = e.to_string();
    s.split(" (os error").next().unwrap_or(&s).to_owned()
}

/// `host:port` as Python's `rpartition(':')` and `strip('[]')` split it.
pub fn split_direct(direct: &str) -> Option<(String, u16)> {
    let (host, port) = direct.rsplit_once(':')?;
    let host = host.trim_matches(|c| c == '[' || c == ']');
    Some((host.to_owned(), port.trim().parse().ok()?))
}

/// The interface MAC without colons (`SenderID`).
pub fn service_id(iface: &str) -> std::io::Result<String> {
    let text = std::fs::read_to_string(format!("/sys/class/net/{iface}/address"))?;
    Ok(text.trim().replace(':', ""))
}

/// The resolved identity, as the sender's TLS configuration.
pub fn sender_from_identity(
    identity: &Identity,
    opts: &Options,
    service_id: String,
) -> Result<Sender, String> {
    let tls =
        omdrop_proto::tls::client_config(identity).map_err(|e| format!("identity error: {e}"))?;
    Ok(Sender {
        tls,
        record: identity.record.clone(),
        computer_name: opts.name.clone(),
        computer_model: opts.model.clone(),
        service_id,
        iface: opts.iface.clone(),
        verbose: opts.verbose,
        auth_tag: opts.auth_tag.clone(),
        should_convert: opts.should_convert,
        op_timeout: opts.op_timeout,
        bound_upload: opts.upload_rto_cap,
    })
}

/// The identity resolver's answer, in the form airdrop-send.py reported it.
pub fn resolve_identity(
    keys: Option<&Path>,
    computer_name: &str,
) -> Result<Identity, IdentityError> {
    omdrop_identity::resolve(&ResolveOptions {
        keys_dir: keys.map(Path::to_path_buf),
        computer_name: Some(computer_name.to_owned()),
        create: true,
    })
}

/// The receiver chosen for the transfer.
struct Chosen<'a> {
    ident: String,
    name: Option<String>,
    client: Client<'a>,
    addr: String,
    port: u16,
}

/// Is `to` a 12-character service id (Python tested only the length)?
fn to_is_id(to: &str) -> bool {
    to.chars().count() == 12
}

/// Run the program. `argv` excludes the program name.
pub fn main(argv: &[String]) -> i32 {
    let opts = match parse_options(argv) {
        Ok(o) => o,
        Err(Exit::Help(text)) => {
            print!("{text}");
            return 0;
        }
        Err(Exit::Error(text)) => {
            eprint!("{text}");
            return 2;
        }
    };
    // A name lookup is not a transfer: keep the debug stream off stdout so the
    // caller can read the name without parsing a log.
    let log = Logger::new(if opts.discover_only {
        Sink::Warnings
    } else {
        Sink::Transfer
    });
    let sid = match service_id(&opts.iface) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "airdrop-send: cannot read the address of {}: {}",
                opts.iface,
                strip_os_error(&e)
            );
            return 1;
        }
    };
    let identity = match resolve_identity(opts.keys.as_deref(), &opts.name) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("identity error: {e}");
            return 1;
        }
    };
    match &identity.record {
        Some(r) => log.wire(&format!("Apple ID validation record found ({} B)", r.len())),
        None => log.wire("no Apple ID validation record; sending without one"),
    }
    if let Ok((chain, _)) = omdrop_proto::tls::client_chain(&identity) {
        // Which vendored intermediate went with the leaf, and whether the
        // leaf verifies to Apple's root through it (the account is not logged).
        let issuer = chain.get(1).map(|c| {
            let pems = omdrop_identity::apple::INTERMEDIATES_PEM;
            let at = pems.iter().position(|pem| {
                rustls::pki_types::pem::PemObject::pem_slice_iter(pem)
                    .filter_map(Result::ok)
                    .any(|d: rustls::pki_types::CertificateDer<'_>| d.as_ref() == c.as_ref())
            });
            let name = at
                .and_then(|i| omdrop_identity::apple::INTERMEDIATE_NAMES.get(i))
                .unwrap_or(&"an unnamed intermediate");
            let verifies =
                !omdrop_identity::apple::certificate_account(chain[0].as_ref()).is_empty();
            format!(
                " (with {name}; leaf verifies to Apple's root: {})",
                if verifies { "yes" } else { "NO" }
            )
        });
        log.wire(&format!(
            "TLS client certificate: {}-certificate chain{}",
            chain.len(),
            issuer.unwrap_or_default()
        ));
    }
    let sender = match sender_from_identity(&identity, &opts, sid) {
        Ok(s) => s,
        Err(msg) => {
            eprintln!("{msg}");
            return 1;
        }
    };
    drop(identity);
    run(&opts, &sender, &log)
}

/// Discover, Ask and Upload with a ready sender.
pub fn run(opts: &Options, sender: &Sender, log: &Logger) -> i32 {
    let mut chosen: Option<Chosen<'_>> = None;

    if let Some(direct) = &opts.direct {
        // Offline / loopback test path: no discovery, the endpoint is given.
        let t1 = Instant::now();
        let try_discover = || {
            split_direct(direct)
                .ok_or_else(|| {
                    PyErr::new("ValueError", &format!("not HOST:PORT: {direct}")).into_io()
                })
                .and_then(|(host, port)| {
                    Ok((Endpoint::resolve(&host, port, &opts.iface)?, host, port))
                })
                .and_then(|(ep, host, port)| {
                    let mut client = Client::new(sender, ep, log);
                    let name = client.discover()?;
                    Ok((client, name, host, port))
                })
        };
        let mut attempt = try_discover();
        // An Apple peer accepts the connection, then restarts its AirDrop
        // server for a sender it classes as legacy, killing that connection
        // before any answer; the server is back milliseconds later. An iPhone
        // in Contacts Only did this to every direct send (R7d, 2026-10-14: its
        // log reads "same account match … accepting connection", then
        // "Restarting AirDrop Bonjour Server for legacy peer"). Nothing has
        // been asked yet, so one more /Discover is safe. A name lookup already
        // makes two attempts, which is why a send by name got through.
        if !opts.discover_only
            && let Err(e) = &attempt
        {
            let py = PyErr::from_io(e);
            if matches!(
                py.class,
                "RemoteDisconnected" | "ConnectionResetError" | "BrokenPipeError"
            ) {
                log.send(&format!(
                    "{} DISCOVER {} failed: {}; retrying once (the peer restarts its AirDrop server on a first connection)",
                    log.t(),
                    direct,
                    py.repr
                ));
                std::thread::sleep(DISCOVER_RETRY_DELAY);
                attempt = try_discover();
            }
        }
        match attempt {
            Ok((client, name, host, port)) => {
                log.send(&format!(
                    "{} DISCOVER {} -> {} ({:.2}s)",
                    log.t(),
                    direct,
                    opt_str_repr(name.as_deref()),
                    t1.elapsed().as_secs_f64()
                ));
                if opts.discover_only {
                    // A peer that answers without naming itself is not an
                    // error: an iPhone answers /Discover with no
                    // ReceiverComputerName unless it recognizes the sender.
                    // Print nothing and exit 0, so the caller tells "no name
                    // offered" from "peer did not answer" (exit 2).
                    if let Some(n) = name.filter(|n| !n.is_empty()) {
                        println!("{n}");
                    }
                    return 0;
                }
                chosen = Some(Chosen {
                    ident: "direct".into(),
                    name,
                    client,
                    addr: host,
                    port,
                });
            }
            Err(e) => {
                let py = PyErr::from_io(&e);
                log.send(&format!(
                    "{} DISCOVER {} failed: {}",
                    log.t(),
                    direct,
                    py.repr
                ));
                // --discover-only silences the debug stream, so without this
                // the failure is invisible: no name, no reason, exit 2.
                if opts.discover_only {
                    eprintln!("{direct}: no answer ({})", py.class);
                }
                return 2;
            }
        }
    }

    if chosen.is_none()
        && let Some(path) = opts.af_log.as_deref().filter(|p| p.exists())
    {
        chosen = af_log_attempts(opts, sender, log, path);
    }

    if chosen.is_none() {
        let browser = match Browser::new(&opts.iface) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("airdrop-send: {e}");
                return 1;
            }
        };
        log.send(&format!(
            "{} browsing _airdrop._tcp on {} from {} as {} ({})",
            log.t(),
            opts.iface,
            browser.ip_addr,
            sender.service_id,
            opts.name
        ));
        let deadline =
            Instant::now() + Duration::try_from_secs_f64(opts.timeout).unwrap_or(Duration::MAX / 4);
        let result = browser.browse(deadline, |found| {
            match on_add(opts, sender, log, found, deadline) {
                Some(c) => {
                    chosen = Some(c);
                    true
                }
                None => false,
            }
        });
        if let Err(e) = result {
            log.wire(&format!("mDNS browse ended: {e}"));
        }
    }

    let Some(mut chosen) = chosen else {
        log.send(&format!(
            "{} no receiver found in {:.0}s",
            log.t(),
            opts.timeout
        ));
        return 2;
    };

    log.send(&format!(
        "{} FOUND {} {} at [{}]:{}; asking",
        log.t(),
        chosen.ident,
        opt_str_repr(chosen.name.as_deref()),
        chosen.addr,
        chosen.port
    ));
    // sharingd tears the /Discover handler down ~1 ms after answering it (a
    // Mac's log, 09-09 04:37:41.059Z). The socket stays open at TCP level
    // with nothing above TCP reading it again, so an Ask on it was ACKed in
    // full and never dispatched, then timed out at +91 s. A real sender
    // throws the Discover connection away; so do we, on every discovery
    // path. The Ask blocks on the receiver's consent prompt, so the new
    // connection carries the long timeout, which then also holds for the
    // Upload on it.
    //
    // A connection that fails here is reported as the Ask failing (exit 3);
    // Python let it escape as a traceback (exit 1) that narrate_send could not
    // explain.
    let t1 = Instant::now();
    let client = &mut chosen.client;
    let asked = client
        .reconnect()
        .and_then(|()| match client.conn.as_mut() {
            Some(c) => c.set_op_timeout(opts.ask_timeout),
            None => Ok(()),
        })
        .and_then(|()| {
            if opts.urls.is_empty() {
                client.ask(&opts.files)
            } else {
                client.ask_links(&opts.urls)
            }
        });
    let ok = match asked {
        Ok(ok) => ok,
        Err(e) => {
            log.send(&format!(
                "{} ASK failed: {}",
                log.t(),
                PyErr::from_io(&e).repr
            ));
            return 3;
        }
    };
    log.send(&format!(
        "{} ASK -> {} ({:.2}s)",
        log.t(),
        if ok { "accepted" } else { "declined" },
        t1.elapsed().as_secs_f64()
    ));
    if !ok {
        return 3;
    }
    if !opts.urls.is_empty() {
        // Accepting the Ask is the delivery: the receiver now opens the link.
        let what = match opts.urls.as_slice() {
            [one] => one.clone(),
            many => format!("{} links", many.len()),
        };
        log.send(&format!("{} LINK {what} -> ok", log.t()));
        return 0;
    }
    let t1 = Instant::now();
    let size: u64 = opts.files.iter().map(|f| f.size).sum();
    let ok = match client.upload(&opts.files) {
        Ok(ok) => ok,
        Err(e) => {
            log.send(&format!(
                "{} UPLOAD failed: {}",
                log.t(),
                PyErr::from_io(&e).repr
            ));
            return 4;
        }
    };
    let what = match opts.files.as_slice() {
        [one] => one.name.clone(),
        many => format!("{} files", many.len()),
    };
    log.send(&format!(
        "{} UPLOAD {what} -> {} ({size} B, {:.2}s)",
        log.t(),
        if ok { "ok" } else { "FAILED" },
        t1.elapsed().as_secs_f64()
    ));
    if ok { 0 } else { 4 }
}

/// The newest af.log endpoint matching --to, re-read before EVERY attempt so
/// a rotated service id, port or host between tries is picked up rather than
/// a stale one retried. --to may be a 12-hex service id (rotates per session
/// on iOS), a MAC (stable for the AWDL session), or a name substring (checked
/// after Discover).
fn af_log_attempts<'a>(
    opts: &Options,
    sender: &'a Sender,
    log: &'a Logger,
    path: &Path,
) -> Option<Chosen<'a>> {
    let freshest = || {
        let eps = endpoints_from_af_log(path).unwrap_or_default();
        eps.into_iter().find(|ep| match opts.to.as_deref() {
            Some(to) if to_is_id(to) => to.eq_ignore_ascii_case(&ep.id),
            Some(to) if to.contains(':') => to.eq_ignore_ascii_case(&ep.sa),
            _ => true,
        })
    };
    // 033602Z: one Discover attempt sent 9 SYNs over 20 s and drew zero
    // SYN-ACKs, while 021922Z's SYN did arrive -- the TX loss is
    // probabilistic, so a single attempt measures nothing. N independent
    // attempts turn it into a rate, bounded overall so a run can never
    // outlive its hold.
    let attempts = opts.af_attempts.max(1);
    let budget = attempts as f64 * (opts.op_timeout_secs + 2.0);
    let deadline =
        Instant::now() + Duration::try_from_secs_f64(budget).unwrap_or(Duration::MAX / 4);
    let mut tried = 0;
    for attempt in 1..=attempts {
        if Instant::now() >= deadline {
            log.send(&format!(
                "{} AF attempts: time budget spent after {tried}/{attempts}",
                log.t()
            ));
            break;
        }
        let Some(ep) = freshest() else {
            log.send(&format!(
                "{} AF attempt {attempt}/{attempts}: no matching endpoint in {}",
                log.t(),
                path.display()
            ));
            break;
        };
        tried = attempt;
        let Some(mac) = omdrop_proto::net::parse_mac(&ep.sa) else {
            continue;
        };
        let addr = omdrop_proto::net::eui64_link_local(mac);
        let age = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0)
            - ep.ts;
        log.send(&format!(
            "{} AF attempt {attempt}/{attempts} endpoint {} from {}: [{addr}]:{} host={} txt={} ({age:.0}s old)",
            log.t(),
            ep.id,
            ep.sa,
            ep.port,
            ep.host.as_deref().unwrap_or("None"),
            ep.txt.as_ref().map_or_else(|| "None".to_owned(), |t| list_repr(t)),
        ));
        let t1 = Instant::now();
        let ep_res = Endpoint::v6(addr, ep.port, Some(&opts.iface));
        let attempt_result = ep_res.and_then(|e| {
            let mut client = Client::new(sender, e, log);
            let name = client.discover()?;
            Ok((client, name))
        });
        let (client, name) = match attempt_result {
            Ok(v) => v,
            Err(e) => {
                log.send(&format!(
                    "{} AF attempt {attempt}/{attempts} DISCOVER {} failed: {} ({:.2}s)",
                    log.t(),
                    ep.id,
                    PyErr::from_io(&e).repr,
                    t1.elapsed().as_secs_f64()
                ));
                continue;
            }
        };
        log.send(&format!(
            "{} AF attempt {attempt}/{attempts} DISCOVER {} -> {} ({:.2}s)",
            log.t(),
            ep.id,
            opt_str_repr(name.as_deref()),
            t1.elapsed().as_secs_f64()
        ));
        let Some(n) = name else { continue };
        if let Some(to) = opts.to.as_deref()
            && !to_is_id(to)
            && !to.contains(':')
            && !n.to_lowercase().contains(&to.to_lowercase())
        {
            continue;
        }
        return Some(Chosen {
            ident: ep.id,
            name: Some(n),
            client,
            addr: addr.to_string(),
            port: ep.port,
        });
    }
    log.send(&format!(
        "{} no usable AirDrop endpoint in {} after {tried} attempt(s); browsing mDNS",
        log.t(),
        path.display()
    ));
    None
}

/// mDNS found a `_airdrop._tcp` instance: Discover it, on this thread.
fn on_add<'a>(
    opts: &Options,
    sender: &'a Sender,
    log: &'a Logger,
    found: crate::mdns::Found,
    deadline: Instant,
) -> Option<Chosen<'a>> {
    let ident = found.name.split('.').next().unwrap_or("").to_owned();
    let addr_texts: Vec<String> = found
        .addrs
        .iter()
        .map(|a| {
            if a.is_unicast_link_local() {
                format!("{a}%{}", opts.iface)
            } else {
                a.to_string()
            }
        })
        .collect();
    let flags_prop = found
        .props
        .iter()
        .find(|(k, _)| k == "flags")
        .map(|(_, v)| v.clone());
    log.send(&format!(
        "{} advert {ident} host={} port={} addr={} flags={}",
        log.t(),
        found.server,
        found.port,
        list_repr(&addr_texts),
        flags_prop.as_deref().unwrap_or("None")
    ));
    let first: Ipv6Addr = *found.addrs.first()?;
    if let Some(to) = opts.to.as_deref() {
        if to_is_id(to) && !to.eq_ignore_ascii_case(&ident) {
            return None;
        }
        // --to as a MAC: only that device (000827Z: the browse Discovered
        // another Mac while the target was hume). Its AWDL link-local is the
        // EUI-64 of the MAC.
        if to.contains(':') {
            let want = omdrop_proto::net::parse_mac(to).map(omdrop_proto::net::eui64_link_local);
            if want.is_none_or(|w| !found.addrs.contains(&w)) {
                log.send(&format!(
                    "{} {ident} at {} is not --to {to}; skipping",
                    log.t(),
                    list_repr(&addr_texts)
                ));
                return None;
            }
        }
    }
    let flags = match flags_prop {
        None => SUPPORTS_DISCOVER,
        Some(v) => v.trim().parse::<i64>().ok()?,
    };
    if flags & SUPPORTS_DISCOVER == 0 {
        log.send(&format!(
            "{} {ident}: no /Discover support (flags {flags:#x}); skipping",
            log.t()
        ));
        return None;
    }
    let endpoint = Endpoint::v6(
        first,
        found.port,
        first.is_unicast_link_local().then_some(opts.iface.as_str()),
    )
    .ok()?;
    let mut client = Client::new(sender, endpoint, log).with_deadline(deadline);
    let t1 = Instant::now();
    let name = match client.discover() {
        Ok(n) => n,
        Err(e) => {
            // Timeouts, resets, TLS: all mean "not this one, not now".
            log.send(&format!(
                "{} DISCOVER {ident} failed: {}",
                log.t(),
                PyErr::from_io(&e).repr
            ));
            return None;
        }
    };
    log.send(&format!(
        "{} DISCOVER {ident} -> {} ({:.2}s)",
        log.t(),
        opt_str_repr(name.as_deref()),
        t1.elapsed().as_secs_f64()
    ));
    let name = name?;
    if let Some(to) = opts.to.as_deref()
        && !to_is_id(to)
        && !name.to_lowercase().contains(&to.to_lowercase())
    {
        log.send(&format!(
            "{} {ident} is {}, not --to {}; skipping",
            log.t(),
            str_repr(&name),
            str_repr(to)
        ));
        return None;
    }
    // The browse deadline bounded the Discover; the transfer gets its own.
    let client = Client::new(sender, client.endpoint.clone(), log);
    let addr = match client.endpoint.addr.ip() {
        IpAddr::V6(_) => addr_texts.first().cloned().unwrap_or_default(),
        IpAddr::V4(v4) => v4.to_string(),
    };
    Some(Chosen {
        ident,
        name: Some(name),
        client,
        addr,
        port: found.port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    fn err(a: &[&str]) -> String {
        match parse_options(&argv(a)) {
            Err(Exit::Error(e)) => e,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn command_line_rules_match_airdrop_send_py() {
        assert!(err(&[]).ends_with(
            "airdrop-send: error: a file or --url is required unless --discover-only\n"
        ));
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.txt");
        std::fs::write(&a, b"x").unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        let b = sub.join("a.txt");
        std::fs::write(&b, b"y").unwrap();
        let a = a.to_str().unwrap();
        let b = b.to_str().unwrap();
        assert!(err(&["--url", "https://x/", a]).contains("send links and files separately"));
        assert!(
            err(&["--url", "ftp://x/"])
                .contains("--url 'ftp://x/': only an http or https link with no spaces")
        );
        assert!(err(&["--url", "https://x/ y"]).contains("only an http or https link"));
        assert!(err(&[a, b]).contains("two of the files have the same name"));
        assert!(err(&["--discover-only"]).contains("--discover-only needs --direct HOST:PORT"));
        assert!(err(&["--auth-tag", "zz", a]).contains("argument --auth-tag"));
        assert!(
            err(&["--op-timeout", "x", a])
                .contains("argument --op-timeout: invalid float value: 'x'")
        );
        let o = parse_options(&argv(&[
            "--discover-only",
            "--direct",
            "[::1]:8771",
            "--op-timeout",
            "2",
        ]))
        .unwrap();
        assert_eq!(o.op_timeout, Some(Duration::from_secs(2)));
        assert_eq!(
            (o.name.as_str(), o.model.as_str(), o.iface.as_str()),
            ("f0010", "MacBookPro18,3", "awdl0")
        );
        let o = parse_options(&argv(&[
            "--url",
            "HTTPS://example.com/",
            "--auth-tag",
            "a1 b2c3",
        ]))
        .unwrap();
        assert_eq!(o.auth_tag, Some(vec![0xa1, 0xb2, 0xc3]));
    }

    #[test]
    fn direct_endpoints_split_like_rpartition() {
        assert_eq!(split_direct("[::1]:8771"), Some(("::1".into(), 8771)));
        assert_eq!(
            split_direct("[fe80::1%awdl0]:8770"),
            Some(("fe80::1%awdl0".into(), 8770))
        );
        assert_eq!(split_direct("127.0.0.1:1"), Some(("127.0.0.1".into(), 1)));
        assert_eq!(split_direct("nowhere"), None);
        assert_eq!(split_direct("[::1]:http"), None);
    }

    #[test]
    fn help_carries_what_omdrop_probes_for() {
        let h = SPEC.help();
        assert!(h.contains("[file ...]") && h.contains("--url"));
    }

    #[test]
    fn the_upload_cap_switch_takes_only_0_or_1() {
        assert_eq!(upload_rto_cap(None), Ok(UPLOAD_RTO_CAP_DEFAULT));
        assert_eq!(upload_rto_cap(Some("")), Ok(UPLOAD_RTO_CAP_DEFAULT));
        assert_eq!(upload_rto_cap(Some("1")), Ok(true));
        assert_eq!(upload_rto_cap(Some("0")), Ok(false));
        for bad in ["yes", "true", " 1", "2"] {
            assert!(upload_rto_cap(Some(bad)).is_err(), "{bad}");
        }
    }
}
