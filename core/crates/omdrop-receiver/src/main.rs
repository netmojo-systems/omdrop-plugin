//! `omdrop-receiver`: serves AirDrop's HTTPS endpoints (`/Discover`, `/Ask`,
//! `/Upload`) on awdl0. A drop-in for omdrop-plugin's `airdrop-serve.py`: the
//! same options, config file, messages, exit codes and log lines.
//!
//! The receiving half only: the radio side hand-builds the AWDL service
//! announcements that actually reach the Macs (an ordinary multicast rarely
//! makes it to the air), so this serves under the identity that side
//! advertises (instance = awdl0 MAC hex, port 8771) and registers nothing over
//! mDNS itself. Runs as the invoking user, never root: it needs no privilege,
//! and received files belong to the user without a chown.

mod args;
mod config;
mod log;
mod server;

use std::fmt::Display;
use std::net::{Ipv6Addr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use omdrop_identity::{Identity, IdentityError, ResolveOptions};
use omdrop_proto::contacts::{self, Visibility};
use omdrop_proto::{archive, net, tls};

use crate::log::{error, info, warning};
use crate::server::{PARTIALS, Server, Settings};

/// The server, once it exists, for the signal thread.
static SERVER: OnceLock<Arc<Server>> = OnceLock::new();

const BIND_ATTEMPTS: u32 = 5;
const BIND_PAUSE: Duration = Duration::from_secs(2);

fn main() {
    std::process::exit(run());
}

/// What `raise SystemExit(message)` did: the message on stderr, status 1.
fn fail(message: impl Display) -> i32 {
    eprintln!("{message}");
    1
}

/// The identity, chosen once at start by the identity contract: the
/// 1Password cache, the files in `~/.omdrop/keys` (or `--keys DIR/keys`), or
/// the self-signed pair, created here if missing. Within a window the choice
/// is the window's; if that identity is unavailable this refuses to start
/// rather than present a different one.
fn resolve_identity(keys: Option<PathBuf>, name: &str) -> Result<Identity, IdentityError> {
    omdrop_identity::resolve(&ResolveOptions {
        keys_dir: keys,
        computer_name: Some(name.to_string()),
        create: true,
    })
}

/// systemd stops this unit with SIGTERM; ^C sends SIGINT. Either way the live
/// sessions are reset (that is what frees the port) and unfinished uploads
/// removed, then the process exits 0. Blocked in every thread and taken by one
/// thread with sigwait, so no handler runs in signal context.
fn handle_stop_signals() -> std::io::Result<()> {
    let mut set = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: sigemptyset initialises `set`; sigaddset and pthread_sigmask
    // get a pointer to that initialised set.
    let set = unsafe {
        libc::sigemptyset(set.as_mut_ptr());
        libc::sigaddset(set.as_mut_ptr(), libc::SIGTERM);
        libc::sigaddset(set.as_mut_ptr(), libc::SIGINT);
        let rc = libc::pthread_sigmask(libc::SIG_BLOCK, set.as_ptr(), std::ptr::null_mut());
        if rc != 0 {
            return Err(std::io::Error::from_raw_os_error(rc));
        }
        set.assume_init()
    };
    std::thread::Builder::new()
        .name("signals".into())
        .spawn(move || {
            loop {
                let mut signal = 0;
                // SAFETY: `set` is an initialised sigset and `signal` a valid out-pointer.
                if unsafe { libc::sigwait(&set, &mut signal) } == 0 {
                    if let Some(server) = SERVER.get() {
                        server.reset_sessions();
                    }
                    PARTIALS.remove_all();
                    std::process::exit(0);
                }
            }
        })?;
    Ok(())
}

/// Lift the soft open-file limit to the hard one. systemd user services start
/// at 1024, and 64 connections (two descriptors each) beside two uploads in
/// progress need headroom. Failure only leaves the default.
fn raise_open_file_limit() {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: a valid out-pointer to an rlimit; setrlimit gets the same.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0 && limit.rlim_cur < limit.rlim_max
        {
            limit.rlim_cur = limit.rlim_max;
            libc::setrlimit(libc::RLIMIT_NOFILE, &limit);
        }
    }
}

fn run() -> i32 {
    // The identity's key is in this process for the life of the window: keep
    // it out of core dumps and away from same-UID ptrace.
    // SAFETY: PR_SET_DUMPABLE takes integer arguments only.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    raise_open_file_limit();

    let default_config = config::default_config_path();
    let args = match args::parse(std::env::args_os(), &default_config.display().to_string()) {
        Ok(a) => a,
        Err(args::Exit::Help(text)) => {
            print!("{text}");
            return 0;
        }
        Err(args::Exit::Usage(text)) => {
            eprint!("{text}");
            return 2;
        }
    };
    let config_path = args.config.clone().unwrap_or(default_config);
    let cfg = match config::load(&config_path) {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    let name = args
        .name
        .clone()
        .or_else(|| cfg.name.clone())
        .unwrap_or_else(config::default_receiver_name);
    let name = match config::validate_name(&name) {
        Ok(n) => n,
        Err(e) => return fail(e),
    };
    let model = args
        .model
        .clone()
        .or_else(|| cfg.model.clone())
        .unwrap_or_else(|| config::DEFAULT_MODEL.into());
    let model = match config::validate_model(&model) {
        Ok(m) => m,
        Err(e) => return fail(e),
    };
    let outdir = args
        .outdir
        .clone()
        .or_else(|| cfg.download_dir.clone())
        .unwrap_or_else(|| {
            config::passwd_home()
                .join("Downloads")
                .display()
                .to_string()
        });
    // Resolved once; never chdir: the cwd is process-wide and the server threaded.
    let dest = match config::validate_download_dir(&outdir) {
        Ok(d) => d,
        Err(e) => return fail(e),
    };
    let percent = args
        .max_receive_percent
        .or(cfg.max_receive_percent)
        .unwrap_or(config::DEFAULT_MAX_RECEIVE_PERCENT);
    let percent = match config::validate_receive_percent(percent) {
        Ok(p) => p as u64,
        Err(e) => return fail(e),
    };
    let Ok(port) = u16::try_from(args.port) else {
        return fail(format!("port {}: must be from 0 to 65535", args.port));
    };
    if args.iface.is_empty() || args.iface.contains('/') {
        return fail(format!(
            "interface {}: not an interface name",
            archive::py_repr(&args.iface)
        ));
    }
    let address_file = format!("/sys/class/net/{}/address", args.iface);
    let sid = match std::fs::read_to_string(&address_file) {
        Ok(text) => text.trim().replace(':', ""),
        Err(e) => return fail(format!("{address_file}: {e}")),
    };
    if let Err(e) = handle_stop_signals() {
        return fail(format!("cannot handle stop signals: {e}"));
    }

    let identity = match resolve_identity(args.keys.clone(), &name) {
        Ok(id) => id,
        Err(e) => return fail(format!("no usable identity: {e}")),
    };
    for w in &identity.warnings {
        warning!("identity: {w}");
    }
    let record_note = identity
        .record
        .as_ref()
        .map(|r| format!(", Apple ID validation record {} bytes", r.len()))
        .unwrap_or_default();
    info!("identity: {}{record_note}", identity.source.as_str());

    // Saves what senders present, for research; it keeps the certificate
    // request alive in Everyone mode so a capture run still sees one.
    let peercert_dir = std::env::var_os("OMDROP_PEERCERT")
        .filter(|d| !d.is_empty())
        .map(PathBuf::from);
    if let Some(dir) = &peercert_dir
        && let Err(e) = std::fs::create_dir_all(dir)
    {
        return fail(format!("OMDROP_PEERCERT {}: {e}", dir.display()));
    }

    // The socket is the IPv6 wildcard, but an interface with no address yet
    // is one no peer can reach: refuse to start and let the unit try again.
    let Some(iface_addr) = net::interface_ipv6(&args.iface) else {
        return fail(format!(
            "interface {} has no IPv6 address yet; is the AWDL radio up?",
            args.iface
        ));
    };

    match archive::sweep_partials(&dest) {
        Ok(0) => {}
        Ok(n) => info!(
            "removed {n} unfinished upload file(s) left in {}",
            dest.display()
        ),
        Err(e) => warning!(
            "could not look for unfinished uploads in {}: {e}",
            dest.display()
        ),
    }

    // A busy port is waited out, never side-stepped: opendrop quietly moved to
    // the next one, which nothing advertises. The usual cause is the previous
    // run's socket still unwinding, which clears in seconds now that stopping
    // resets its sessions.
    let mut listener = None;
    for attempt in 1..=BIND_ATTEMPTS {
        match TcpListener::bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, port))) {
            Ok(l) => {
                listener = Some(l);
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {}
            Err(e) => return fail(format!("cannot listen on port {port}: {e}")),
        }
        warning!("port {port} still held; retry {attempt} of {BIND_ATTEMPTS}");
        std::thread::sleep(BIND_PAUSE);
    }
    let Some(listener) = listener else {
        error!(
            "port {port} is still held by something else after waiting; the announcer only ever names {port}"
        );
        return 1;
    };

    // Who signed a sender's certificate is decided after the handshake by the
    // Contacts policy, which verifies the chain to Apple itself; a sender that
    // does not chain is refused at /Discover or /Ask. Contacts Only asks for one,
    // because it binds the sender's validation record to the connection;
    // Everyone mode does not ask, since no code would consult it.
    let visibility_path = contacts::visibility_path();
    let client_auth = if contacts::visibility(&visibility_path) == Visibility::Contacts
        || peercert_dir.is_some()
    {
        let pems: Vec<&[u8]> = std::iter::once(omdrop_identity::apple::ROOT_CA_PEM)
            .chain(omdrop_identity::apple::INTERMEDIATES_PEM.iter().copied())
            .collect();
        let hint_subjects = tls::hint_subjects(&pems).unwrap_or_else(|e| {
            warning!("could not read Apple's CA names for the certificate request: {e}");
            Vec::new()
        });
        tls::ClientAuth::Request { hint_subjects }
    } else {
        tls::ClientAuth::None
    };
    let tls_config = match tls::server_config(&identity, client_auth) {
        Ok(c) => c,
        Err(e) => return fail(format!("no usable identity: {e}")),
    };

    info!("config {}: {}", config_path.display(), cfg.summary());
    info!(
        "serving {sid}._airdrop._tcp.local as {name} ({model}) on [{iface_addr}]:{port}, receiving into {}",
        dest.display()
    );
    let settings = Settings {
        name,
        model,
        dest,
        max_receive_percent: percent,
        record: identity.record.clone(),
        peercert_dir,
        visibility_path,
        known_senders_path: contacts::known_senders_path(),
        min_free_bytes: server::MIN_FREE_BYTES,
        limits: server::ConnLimits::default(),
        iface: args.iface.clone(),
    };
    drop(identity);
    let server = Arc::new(Server::new(settings, tls_config));
    let _ = SERVER.set(Arc::clone(&server));
    server.serve(listener);
    0
}
