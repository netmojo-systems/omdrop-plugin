//! `send-to-peer`: send files to an AWDL peer without waiting for an mDNS
//! advert (drop-in for omdrop-awdl's `userspace/send-to-peer`).
//!
//! 2026-09-18: two transfers landed on a Mac by dialling its EUI-64
//! link-local address directly. Discovery was never the problem and mDNS was
//! never the channel: a Mac in Everyone mode answers /Discover with no Finder
//! AirDrop window open and publishes no `_airdrop._tcp` instance at all, so a
//! sender that waits for one waits forever. The firmware peer table already
//! holds every MAC we can hear, and a link-local address is a pure function of
//! a MAC, so the endpoint needs no discovery protocol.
//!
//! Peers come from the radio helper's `peers`, which needs root, so it runs
//! through pkexec. Everything else runs as the user. Name lookups (`-n`,
//! `--mac NAME`) run in process through this crate's client; the transfer
//! itself runs the `airdrop-send` program, so `--print` shows a command that
//! does exactly what the send would.
//!
//! Output that callers parse, kept verbatim: the `--list` rows
//! (`MAC  -47 dBm  [fe80::...%awdl0]:8770  NAME`, read by `omdrop`'s
//! choose_peer, find_by_name and peers_json, and through `omdrop peers --json`
//! by the panel), the `(no response)`/`(anonymous)` placeholders, the
//! `no devices found` sentence with exit 1, the ` never opened ` line that
//! `omdrop`'s send_errors rewrites, and `--help` (probed for `[file ...]`,
//! `--url`, `--names`, `--stream`).

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::Ipv6Addr;
use std::sync::{Condvar, Mutex, PoisonError, mpsc};
use std::time::Duration;

use crate::args::{self, Exit, Kind, Opt, Spec};
use crate::client::clean_peer_name;
use crate::pyfmt::float_str;

pub const AIRDROP_PORT: u16 = 8770;
pub const IFACE: &str = "awdl0";
/// The advert's ceiling for a name lookup, and the deadline its knocks wait
/// to. Not a sleep: the receiver binds its port in milliseconds, but reaching
/// it took 14.8 s in the run that worked, so the knock keeps trying to this
/// deadline instead of guessing how long to wait. There is nothing to wait
/// for once we stop transmitting. A send waits, and advertises, for its own
/// --wait.
pub const WAKE_SECONDS: f64 = 30.0;
/// How long to wait for the advertiser to say it registered.
pub const WAKE_READY: f64 = 5.0;
/// How often a lookup re-reads the peer table for newcomers.
pub const RESCAN_SECONDS: f64 = 2.0;
/// Sixteen covers the eight-entry firmware table plus the watcher's registrations.
const LOOKUP_WORKERS: usize = 16;
pub const NAMING_PURPOSE: &str = "naming peers that are already listening";

const NO_DEVICES: &str = "no devices found: nothing nearby is advertising. A window has to be open for the peer watcher to fill this.";

static OPTS: &[Opt] = &[
    Opt {
        long: "--url",
        short: None,
        kind: Kind::Append,
    },
    Opt {
        long: "--mac",
        short: None,
        kind: Kind::Value,
    },
    Opt {
        long: "--list",
        short: None,
        kind: Kind::Flag,
    },
    Opt {
        long: "--print",
        short: None,
        kind: Kind::Flag,
    },
    Opt {
        long: "--port",
        short: None,
        kind: Kind::Value,
    },
    Opt {
        long: "--name",
        short: None,
        kind: Kind::Value,
    },
    Opt {
        long: "--op-timeout",
        short: None,
        kind: Kind::Value,
    },
    Opt {
        long: "--wait",
        short: None,
        kind: Kind::Value,
    },
    Opt {
        long: "--names",
        short: Some("-n"),
        kind: Kind::Flag,
    },
    Opt {
        long: "--no-wake",
        short: None,
        kind: Kind::Flag,
    },
    Opt {
        long: "--stream",
        short: None,
        kind: Kind::Flag,
    },
];

pub static SPEC: Spec = Spec {
    prog: "send-to-peer",
    usage: "usage: send-to-peer [-h] [--url URL] [--mac NAME|ADDRESS] [--list] [--print]
                    [--port PORT] [--name NAME] [--op-timeout OP_TIMEOUT]
                    [--wait SECONDS] [-n] [--no-wake] [--stream]
                    [file ...]",
    help_body: "Send files to an AWDL peer without waiting for an mDNS advert.

2026-09-18: two transfers landed on a Mac by dialling its EUI-64 link-local
directly. Discovery was never the problem and mDNS was never the channel -- a
Mac in Everyone mode answers /Discover with no Finder AirDrop window open and
publishes no `_airdrop._tcp` instance at all, so a sender that waits for one
waits forever. The firmware peer table already holds every MAC we can hear,
and a link-local address is a pure function of a MAC, so the endpoint needs no
discovery protocol.

  send-to-peer --list                 # what can we hear, and where
  send-to-peer FILE                   # the only peer, or --mac to choose
  send-to-peer --mac e2:9d:.. FILE
  send-to-peer --mac hume --url https://example.com/   # a link, opened there
  send-to-peer --print FILE           # show the command, send nothing

Peers come from the radio helper's `peers`, which needs root, so this runs it
through pkexec. Everything else runs as you.

positional arguments:
  file                  files to send, as one transfer the peer accepts once

options:
  -h, --help            show this help message and exit
  --url URL             send this http(s) link instead of files; the peer
                        opens it in its browser. Repeat for several
  --mac NAME|ADDRESS    who to send to: a peer name, or part of its address.
                        Default is the only device heard
  --list                list peers and their endpoints
  --print               print the sender command without running it
  --port PORT
  --name NAME           SenderComputerName the peer shows. Default: the short
                        hostname
  --op-timeout OP_TIMEOUT
                        seconds to wait on each request; /Ask waits for a
                        human
  --wait SECONDS        poll the peer's port and send the moment it opens; an
                        iPhone only listens in bursts
  -n, --names           ask each peer for its name over /Discover (reveals
                        this machine to every peer listed)
  --no-wake             do not advertise over BLE while asking for names or
                        waiting to send; only peers already listening answer
  --stream              with --list --names, print each peer as soon as it
                        answers
",
    opts: OPTS,
};

/// Everything outside this process: the peer table, the network, the clock,
/// the BLE advert and the sender program. The real one is
/// [`crate::peer_env::RealEnv`]; tests substitute their own.
pub trait Env: Sync {
    /// Monotonic seconds.
    fn monotonic(&self) -> f64;
    fn sleep(&self, secs: f64);
    /// The peer table, strongest signal first; `Err` is the helper's failure
    /// message (not an empty room).
    fn peers(&self) -> Result<Vec<(String, Option<i64>)>, String>;
    /// Is anything accepting TCP there right now?
    fn listening(&self, host: Ipv6Addr, port: u16, timeout: f64) -> bool;
    /// Start the BLE advert and wait for it to register: (running, note). A
    /// note is a one-line reason the wake did not happen. `(false, None)`:
    /// no advertiser installed, nothing to say.
    fn wake_start(&self, seconds: f64) -> (bool, Option<String>);
    /// Stop the advert and reap it.
    fn wake_stop(&self);
    /// Ask one peer its name: the name, `""` when it answered without one,
    /// `None` when it did not answer.
    fn peer_name(
        &self,
        mac: &str,
        port: u16,
        sender_name: &str,
        ready_by: Option<f64>,
    ) -> Option<String>;
    /// The sender program's argv prefix (`.../airdrop-send`).
    fn sender_command(&self) -> Vec<String>;
    /// Run the sender; its exit status.
    fn run_sender(&self, cmd: &[String]) -> i32;
    /// How often a lookup with a wake re-reads the table.
    fn rescan_seconds(&self) -> f64 {
        RESCAN_SECONDS
    }
}

/// MAC -> EUI-64 link-local, the address an Apple peer answers on.
pub fn link_local(mac: &str) -> Option<Ipv6Addr> {
    omdrop_proto::net::parse_mac(mac).map(omdrop_proto::net::eui64_link_local)
}

/// A peer registered this window but absent from the current advertisers
/// snapshot has no signal reading. Say so; a fabricated number would be worse
/// than a blank.
pub fn signal(rssi: Option<i64>) -> String {
    match rssi {
        Some(r) => format!("{r:>4} dBm"),
        None => "   ? dBm".to_owned(),
    }
}

/// The advert, up for as long as this guard lives. Stopping it is the drop,
/// so an early return or a panic still takes the advert down.
pub struct Wake<'e, E: Env + ?Sized> {
    env: &'e E,
    /// The absolute deadline the wake lasts until, or `None` when no wake of
    /// ours is up and there is nothing to wait for.
    pub deadline: Option<f64>,
}

impl<E: Env + ?Sized> Drop for Wake<'_, E> {
    fn drop(&mut self) {
        self.env.wake_stop();
    }
}

/// Advertise ourselves over BLE for as long as we are asking peers to talk.
///
/// A Contacts Only device keeps its AirDrop server shut until a sender's BLE
/// Continuity advert presents contact hashes it recognizes. Measured against
/// a Mac on 2026-09-21: with zero hashes it logged the advert UNRECOGNIZED
/// and started nothing; with this account's own hashes it recognized them,
/// bound 8770 22 ms later, and the listing that had failed all day returned
/// the peer's name. Without an Apple ID record the advertiser sends zero
/// hashes, which still wakes a receiver set to Everyone.
///
/// Silent when there is nothing to run. A wake that was supposed to work and
/// did not says so on stderr, followed by `purpose`: what the caller carries
/// on doing without it.
pub fn wake<'e, E: Env + ?Sized>(
    env: &'e E,
    seconds: f64,
    purpose: &str,
    err: &mut dyn Write,
) -> Wake<'e, E> {
    let (running, note) = env.wake_start(seconds);
    if let Some(note) = &note {
        let _ = writeln!(err, "{note}; {purpose}");
    }
    let deadline = (running && note.is_none()).then(|| env.monotonic() + seconds);
    Wake { env, deadline }
}

/// Wait for a peer's AirDrop port to answer, up to an absolute deadline.
///
/// Two 3 s knocks when there is no deadline (`--no-wake`, a failed advert):
/// without a wake of our own there is nothing to wait for, and an absent peer
/// should cost a listing seconds rather than half a minute. 3 s, not 1.5: the
/// first connection to an idle Mac takes about a second and sometimes longer,
/// and a 1.5 s knock reported a listening Mac absent in 3 of 8 lookups.
///
/// With a deadline, every socket wait is capped by the time left, so this can
/// overrun neither the wake's ceiling nor the caller's cap. A refusal comes
/// back instantly and means the stack is there and the service is not, so it
/// is paced rather than spun on.
pub fn knock<E: Env + ?Sized>(env: &E, host: Ipv6Addr, port: u16, ready_by: Option<f64>) -> bool {
    let Some(ready_by) = ready_by else {
        return (0..2).any(|_| env.listening(host, port, 3.0));
    };
    loop {
        let left = ready_by - env.monotonic();
        if left <= 0.0 {
            return false;
        }
        let t0 = env.monotonic();
        if env.listening(host, port, left.min(3.0)) {
            return true;
        }
        let spent = env.monotonic() - t0;
        if spent < 1.0 {
            env.sleep((1.0 - spent).min((ready_by - env.monotonic()).max(0.0)));
        }
    }
}

/// How many /Discover attempts a peer gets, and each one's timeout.
///
/// A peer that answered a knock gets three at 8 s; one that ignored the
/// knocks gets a single 3 s ask, so a listing of absent devices stays in
/// seconds. One ask is still made: even two knocks miss a listening Mac about
/// 1 in 8 (it is restarting its Bonjour server), and reporting a receiving
/// device as absent without asking it is the error that matters.
///
/// Why three: a lookup against a listening Mac fails sometimes and the cause
/// is not established. 2026-09-20, sequential runs: knock plus two attempts
/// named it 3 times in 4, two attempts with no knock 4 in 4; 6 of 8 first
/// attempts answered and 8 of 8 within two. The receiver's log shows one
/// server restart across 42 DISCOVERs, so "the knock eats a sacrificial
/// connection" is not supported. Retries cost little; a wrong "nothing
/// answered" hides a device you could name and send to.
pub fn lookup_budget(knocked: bool) -> (u32, f64) {
    if knocked { (3, 8.0) } else { (1, 3.0) }
}

/// A counting semaphore for the lookup pool.
struct Slots {
    free: Mutex<usize>,
    cv: Condvar,
}

impl Slots {
    // A counter has no invariant a panicking holder could break, so a
    // poisoned lock is taken over rather than propagated.
    fn acquire(&self) {
        let mut free = self.free.lock().unwrap_or_else(PoisonError::into_inner);
        while *free == 0 {
            free = self.cv.wait(free).unwrap_or_else(PoisonError::into_inner);
        }
        *free -= 1;
    }

    fn release(&self) {
        *self.free.lock().unwrap_or_else(PoisonError::into_inner) += 1;
        self.cv.notify_one();
    }
}

/// Name every peer at once. Serially this costs seconds per peer, and a
/// listing is something a person waits on.
///
/// The wake wraps the whole batch rather than each peer: one advert reaches
/// every device in range, and the probes are concurrent anyway. They share
/// one absolute deadline for the same reason -- it is the advert that is
/// running out, not each peer's patience -- so a slow peer cannot push the
/// listing past the moment we stop transmitting.
///
/// `on_result` is called the moment each peer's answer is known, so a caller
/// can show a name seconds after it arrives rather than when the slowest
/// peer gives up. `rescan` returns the MACs heard now; while the wake is up
/// it is called every [`Env::rescan_seconds`] and any MAC not yet asked is
/// asked in this same lookup: the firmware table holds eight entries and
/// churns, and a device that arrived just after the lookup started otherwise
/// waited for the next one, half a minute later.
///
/// Returns each peer's answer in the order the answers arrived.
#[allow(clippy::too_many_arguments)]
pub fn peer_names<E: Env + ?Sized>(
    env: &E,
    macs: &[String],
    port: u16,
    sender_name: &str,
    with_wake: bool,
    on_result: &mut dyn FnMut(&str, Option<&str>),
    mut rescan: Option<&mut dyn FnMut() -> Vec<String>>,
    err: &mut dyn Write,
) -> Vec<(String, Option<String>)> {
    let guard = with_wake.then(|| wake(env, WAKE_SECONDS, NAMING_PURPOSE, err));
    let ready_by = guard.as_ref().and_then(|g| g.deadline);
    let slots = Slots {
        free: Mutex::new(LOOKUP_WORKERS),
        cv: Condvar::new(),
    };
    let mut results: Vec<(String, Option<String>)> = Vec::new();
    std::thread::scope(|s| {
        let (tx, rx) = mpsc::channel::<(String, Option<String>)>();
        let slots = &slots;
        let ask = |mac: String| {
            let tx = tx.clone();
            s.spawn(move || {
                slots.acquire();
                // Cleaned whatever Env answered: every row, match and
                // listing below shows these names.
                let name = env
                    .peer_name(&mac, port, sender_name, ready_by)
                    .map(|n| clean_peer_name(&n).unwrap_or_default());
                slots.release();
                let _ = tx.send((mac, name));
            });
        };
        let mut asked: HashSet<String> = HashSet::new();
        let mut pending = 0usize;
        for m in macs {
            if asked.insert(m.clone()) {
                ask(m.clone());
                pending += 1;
            }
        }
        let every =
            Duration::try_from_secs_f64(env.rescan_seconds()).unwrap_or(Duration::from_secs(2));
        while pending > 0 {
            let first = if rescan.is_some() {
                rx.recv_timeout(every).ok()
            } else {
                rx.recv().ok()
            };
            let mut got: Vec<(String, Option<String>)> = first.into_iter().collect();
            got.extend(rx.try_iter());
            for (mac, name) in got {
                pending -= 1;
                on_result(&mac, name.as_deref());
                results.push((mac, name));
            }
            // Newcomers only while we are still transmitting: once the wake
            // ends there is nothing to wake them with, and a lookup without
            // one should stay in seconds.
            if let Some(rescan) = rescan.as_mut()
                && ready_by.is_some_and(|d| env.monotonic() < d)
            {
                for m in rescan() {
                    if asked.insert(m.clone()) {
                        ask(m);
                        pending += 1;
                    }
                }
            }
        }
    });
    drop(guard);
    results
}

fn usage_exit(e: Exit, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    match e {
        Exit::Help(text) => {
            let _ = out.write_all(text.as_bytes());
            0
        }
        Exit::Error(text) => {
            let _ = err.write_all(text.as_bytes());
            2
        }
    }
}

/// Is `want` (lower-cased) an address rather than a name? An address carries
/// a colon, or is a full 12-hex MAC. Anything else is a name, and the test
/// has to be that strict: real device names are often pure hex ("f0011" is a
/// machine here), and treating one as an address fragment would silently
/// target the wrong device.
pub fn is_address(want: &str) -> bool {
    want.contains(':')
        || (want.len() == 12
            && want
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}

/// Run the program. `argv` excludes the program name.
pub fn main<E: Env + ?Sized>(
    env: &E,
    argv: &[String],
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let p = match SPEC.parse(argv) {
        Ok(p) => p,
        Err(e) => return usage_exit(e, out, err),
    };
    let parsed = (|| -> Result<(i64, f64, f64), Exit> {
        Ok((
            SPEC.int(&p, "--port", AIRDROP_PORT.into())?,
            SPEC.float(&p, "--op-timeout", 60.0)?,
            SPEC.float(&p, "--wait", 0.0)?,
        ))
    })();
    let (port, op_timeout, wait_secs) = match parsed {
        Ok(v) => v,
        Err(e) => return usage_exit(e, out, err),
    };
    let Ok(port) = u16::try_from(port) else {
        return usage_exit(
            SPEC.error(&format!("argument --port: invalid port: {port}")),
            out,
            err,
        );
    };
    if let Err(e) = args::timeout(&SPEC, "--wait", wait_secs.max(0.0)) {
        return usage_exit(e, out, err);
    }
    let name = p
        .value("--name")
        .map_or_else(omdrop_identity::short_hostname, str::to_owned);
    let urls = p.all("--url");
    let files = p.positionals.clone();
    let do_wake = !p.flag("--no-wake");

    let heard = match env.peers() {
        Ok(h) => h,
        Err(msg) => {
            let _ = writeln!(err, "{msg}");
            return 4;
        }
    };

    if p.flag("--list") {
        if heard.is_empty() {
            let _ = writeln!(out, "{NO_DEVICES}");
            return 1;
        }
        let rssi_of: RefCell<HashMap<String, Option<i64>>> =
            RefCell::new(heard.iter().cloned().collect());
        let row = |mac: &str, got: Option<&str>, named: bool| -> String {
            let rssi = rssi_of.borrow().get(mac).copied().flatten();
            let ll = link_local(mac).map(|a| a.to_string()).unwrap_or_default();
            let mut line = format!("{mac}  {}  [{ll}%{IFACE}]:{port}", signal(rssi));
            if named {
                // Three outcomes, three words. "(no response)", not "(not
                // receiving)": all we observe is that nothing answered on the
                // AirDrop port, and a device mid-restart of its Bonjour server
                // produces that too.
                let shown = match got {
                    Some("") => "(anonymous)",
                    Some(n) => n,
                    None => "(no response)",
                };
                line.push_str("  ");
                line.push_str(shown);
            }
            line
        };
        if !p.flag("--names") {
            for (mac, _) in &heard {
                let _ = writeln!(out, "{}", row(mac, None, false));
            }
            return 0;
        }
        // A table read that fails mid-lookup is not a reason to stop naming
        // the peers already heard; it just finds no newcomers this time.
        let mut rescan = || -> Vec<String> {
            let Ok(now) = env.peers() else {
                return Vec::new();
            };
            let mut map = rssi_of.borrow_mut();
            for (m, r) in &now {
                map.entry(m.clone()).or_insert(*r);
            }
            now.into_iter().map(|(m, _)| m).collect()
        };
        let stream = p.flag("--stream");
        let macs: Vec<String> = heard.iter().map(|(m, _)| m.clone()).collect();
        // --stream prints each row the moment its answer is in. Without it
        // the whole listing comes at the end, in signal order.
        let names = {
            let mut on_result = |m: &str, n: Option<&str>| {
                if stream {
                    let _ = writeln!(out, "{}", row(m, n, true));
                    let _ = out.flush();
                }
            };
            peer_names(
                env,
                &macs,
                port,
                &name,
                do_wake,
                &mut on_result,
                Some(&mut rescan),
                err,
            )
        };
        if !stream {
            let named: HashMap<&str, Option<&str>> = names
                .iter()
                .map(|(m, n)| (m.as_str(), n.as_deref()))
                .collect();
            let mut order: Vec<&str> = macs.iter().map(String::as_str).collect();
            order.extend(
                names
                    .iter()
                    .map(|(m, _)| m.as_str())
                    .filter(|m| !macs.iter().any(|h| h == m)),
            );
            for mac in order {
                let _ = writeln!(out, "{}", row(mac, named.get(mac).copied().flatten(), true));
            }
        }
        return 0;
    }

    if files.is_empty() && urls.is_empty() {
        return usage_exit(
            SPEC.error("a file or --url is required unless --list"),
            out,
            err,
        );
    }
    if !files.is_empty() && !urls.is_empty() {
        return usage_exit(
            SPEC.error("send links and files separately: a transfer carries one or the other"),
            out,
            err,
        );
    }

    let mac = if let Some(given) = p.value("--mac") {
        let want = given.to_lowercase();
        let known: Vec<String> = heard.iter().map(|(m, _)| m.clone()).collect();
        // A person sending a file knows who they are sending to, not what
        // MAC that device is wearing this minute; the MAC rotates every few
        // minutes, so it is the worse handle of the two.
        let matches: Vec<String> = if is_address(&want) {
            known
                .iter()
                .filter(|m| m.contains(&want))
                .cloned()
                .collect()
        } else {
            // Resolving the name IS the request, so here asking is not
            // optional. It works precisely when it matters: a device can only
            // receive the file if it is already listening.
            let names = peer_names(env, &known, port, &name, do_wake, &mut |_, _| {}, None, err);
            let matches: Vec<String> = names
                .iter()
                .filter(|(_, n)| {
                    n.as_deref()
                        .is_some_and(|n| !n.is_empty() && n.to_lowercase().contains(&want))
                })
                .map(|(m, _)| m.clone())
                .collect();
            if matches.is_empty() {
                let _ = writeln!(
                    err,
                    "no device answering to \"{given}\" is receiving right now."
                );
                let named: Vec<(&String, &str)> = names
                    .iter()
                    .filter_map(|(m, n)| n.as_deref().filter(|n| !n.is_empty()).map(|n| (m, n)))
                    .collect();
                if named.is_empty() {
                    let _ = writeln!(
                        err,
                        "  no peer would give a name: a device is named only while it is receiving, so open AirDrop on it first."
                    );
                } else {
                    let _ = writeln!(err, "  these named themselves:");
                    for (m, n) in named {
                        let _ = writeln!(err, "    {n}  ({m})");
                    }
                }
                return 2;
            }
            matches
        };
        if matches.len() > 1 {
            let _ = writeln!(err, "\"{given}\" matches more than one device:");
            for m in &matches {
                let _ = writeln!(err, "    {m}");
            }
            return 2;
        }
        let Some(mac) = matches.into_iter().next() else {
            let _ = writeln!(
                err,
                "{given} is not in the peer table; --list shows what is"
            );
            return 2;
        };
        mac
    } else {
        match heard.as_slice() {
            [(only, _)] => only.clone(),
            [] => {
                let _ = writeln!(err, "{NO_DEVICES}");
                return 2;
            }
            several => {
                let _ = writeln!(err, "several peers heard; choose one with --mac:");
                for (m, rssi) in several {
                    let _ = writeln!(err, "  {m}  {}", signal(*rssi));
                }
                return 2;
            }
        }
    };

    let Some(ll) = link_local(&mac) else {
        let _ = writeln!(err, "not a MAC: {mac}");
        return 2;
    };
    let target = format!("[{ll}%{IFACE}]:{port}");
    // "--" so a file whose name begins with a dash is a file, not an option.
    let mut cmd = env.sender_command();
    cmd.extend([
        "--direct".to_owned(),
        target.clone(),
        "--op-timeout".to_owned(),
        float_str(op_timeout),
        "--name".to_owned(),
        name.clone(),
    ]);
    for u in &urls {
        cmd.extend(["--url".to_owned(), u.clone()]);
    }
    cmd.push("--".to_owned());
    cmd.extend(files.iter().cloned());
    if p.flag("--print") {
        let _ = writeln!(out, "{}", cmd.join(" "));
        return 0;
    }

    // An iPhone does not keep an AirDrop server listening while it is merely
    // discoverable: measured 2026-09-18, port 8770 refused instantly, was open
    // for seconds around other sharingd work, and was gone a minute later.
    // Two transfers landed by firing inside that window. Waiting alone relied
    // on something else waking the phone, and choosing a file closes the
    // panel whose lookups did; so the wait raises the same wake the lookups
    // use, for as long as it waits, and stops it before the transfer starts.
    if wait_secs > 0.0 && !env.listening(ll, port, 2.0) {
        let _ = writeln!(
            err,
            "waiting up to {wait_secs:.0}s for {mac} to start listening on {port}"
        );
        let mut opened = false;
        {
            let _guard = do_wake.then(|| wake(env, wait_secs, "waiting without a wake", err));
            let deadline = env.monotonic() + wait_secs;
            while env.monotonic() < deadline {
                if env.listening(ll, port, 2.0) {
                    opened = true;
                    break;
                }
                env.sleep(1.0);
            }
        }
        if !opened {
            let _ = writeln!(
                err,
                "{mac} never opened {port}; on an iPhone, open a share sheet or receive something to wake sharingd"
            );
            return 3;
        }
    }

    let items = if urls.is_empty() { &files } else { &urls };
    let what = match items.as_slice() {
        [one] => one.clone(),
        many if urls.is_empty() => format!("{} files", many.len()),
        many => format!("{} links", many.len()),
    };
    let _ = writeln!(err, "sending {what} to {mac} at {target}");
    let _ = err.flush();
    env.run_sender(&cmd)
}

/// Parse the radio helper's `peers` output: every `MAC  rssi=N` or
/// `MAC  rssi=?` pair (backend contract: `(-?\d+|\?)`; a backend without a
/// signal reading prints `?`), first occurrence's position, last
/// occurrence's value (a Python dict's order). `?` is `None`, which the
/// listing shows as `   ? dBm`.
pub fn parse_peer_table(text: &str) -> Vec<(String, Option<i64>)> {
    let mut found: Vec<(String, Option<i64>)> = Vec::new();
    for line in text.lines() {
        if let Some((mac, rssi)) = find_mac_rssi(line) {
            match found.iter_mut().find(|(m, _)| *m == mac) {
                Some(slot) => slot.1 = rssi,
                None => found.push((mac, rssi)),
            }
        }
    }
    found
}

/// The first lower-case MAC in `s` at or after `from`: (start, mac).
fn find_mac(s: &str, from: usize) -> Option<(usize, String)> {
    let b = s.as_bytes();
    let hex = |c: u8| c.is_ascii_digit() || (b'a'..=b'f').contains(&c);
    (from..b.len().saturating_sub(16)).find_map(|i| {
        let w = b.get(i..i + 17)?;
        let ok = w
            .iter()
            .enumerate()
            .all(|(j, &c)| if j % 3 == 2 { c == b':' } else { hex(c) });
        ok.then(|| (i, String::from_utf8_lossy(w).into_owned()))
    })
}

/// `([0-9a-f]{2}(?::[0-9a-f]{2}){5})\s+rssi=\s*(-?\d+|\?)`, first match;
/// `?` gives `None`.
fn find_mac_rssi(line: &str) -> Option<(String, Option<i64>)> {
    let mut from = 0;
    while let Some((i, mac)) = find_mac(line, from) {
        let rest = line.get(i + 17..).unwrap_or("");
        let after_ws = rest.trim_start();
        if after_ws.len() < rest.len()
            && let Some(v) = after_ws.strip_prefix("rssi=")
        {
            let v = v.trim_start();
            if v.starts_with('?') {
                return Some((mac, None));
            }
            let neg = v.starts_with('-');
            let digits: String = v
                .trim_start_matches('-')
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            if !digits.is_empty() && (!neg || v.len() > 1) {
                let n: i64 = digits.parse().unwrap_or(i64::MAX);
                return Some((mac, Some(if neg { -n } else { n })));
            }
        }
        from = i + 1;
    }
    None
}

/// MACs in `ip -6 neigh show dev awdl0 nud permanent` output (`lladdr MAC`).
pub fn parse_neigh(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find("lladdr") {
        let after = rest.get(i + 6..).unwrap_or("");
        let trimmed = after.trim_start();
        if trimmed.len() < after.len()
            && let Some((0, mac)) = find_mac(trimmed, 0)
        {
            out.push(mac);
        }
        rest = after;
    }
    out
}

/// Merge the table with the watcher's registrations, drop our own address,
/// and sort strongest first, unknown signal last (stable).
pub fn merge_peers(
    mut found: Vec<(String, Option<i64>)>,
    registered: Vec<String>,
    own: Option<&str>,
) -> Vec<(String, Option<i64>)> {
    // The advertisers table is a live snapshot that empties between reads:
    // sampled every four seconds on 2026-09-20 it reported nobody in four
    // reads of five while three peers were audible. The peer watcher's
    // registrations are the durable record; a peer seen only there has no
    // RSSI, which is worth saying rather than inventing a number.
    for mac in registered {
        if !found.iter().any(|(m, _)| *m == mac) {
            found.push((mac, None));
        }
    }
    // Both sources can include this machine's own AWDL address (issue 12).
    if let Some(own) = own {
        found.retain(|(m, _)| m != own);
    }
    found.sort_by_key(|(_, r)| (r.is_none(), -(r.unwrap_or(0) as i128)));
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_signal_is_a_peer_without_rssi() {
        let text = "b2:c4:98:5e:e6:be rssi=?\n22:8b:38:31:89:4e  rssi= -34\nf2:f2:ee:c4:5a:f7 rssi=  ? (no reading)\n";
        let peers = merge_peers(parse_peer_table(text), Vec::new(), None);
        assert_eq!(
            peers,
            vec![
                ("22:8b:38:31:89:4e".into(), Some(-34)),
                ("b2:c4:98:5e:e6:be".into(), None),
                ("f2:f2:ee:c4:5a:f7".into(), None),
            ]
        );
        assert_eq!(signal(peers[1].1), "   ? dBm");
    }

    #[test]
    fn peer_table_parsing() {
        let text = "advertisers:\n  e2:9d:03:6c:58:23  rssi= -47 ch 6\n  fe:63:e6:68:9f:12 rssi=-14\n  junk 12:34 rssi=1\n  e2:9d:03:6c:58:23  rssi=-50\n  AA:BB:CC:DD:EE:FF rssi=-1\n";
        assert_eq!(
            parse_peer_table(text),
            vec![
                ("e2:9d:03:6c:58:23".into(), Some(-50)),
                ("fe:63:e6:68:9f:12".into(), Some(-14))
            ]
        );
        let neigh = "fe80::1 lladdr 16:2f:da:27:3d:76 PERMANENT\nfe80::2 lladdr  02:00:00:00:00:01 PERMANENT\n";
        assert_eq!(
            parse_neigh(neigh),
            ["16:2f:da:27:3d:76", "02:00:00:00:00:01"]
        );
        let merged = merge_peers(
            parse_peer_table(text),
            parse_neigh(neigh),
            Some("02:00:00:00:00:01"),
        );
        assert_eq!(
            merged,
            vec![
                ("fe:63:e6:68:9f:12".into(), Some(-14)),
                ("e2:9d:03:6c:58:23".into(), Some(-50)),
                ("16:2f:da:27:3d:76".into(), None)
            ]
        );
    }

    #[test]
    fn signal_and_address_rules() {
        assert_eq!(signal(Some(-47)), " -47 dBm");
        assert_eq!(signal(Some(-5)), "  -5 dBm");
        assert_eq!(signal(None), "   ? dBm");
        assert!(is_address("e2:9d"));
        assert!(is_address("e29d036c5823"));
        assert!(!is_address("f0011"));
        assert!(!is_address("hume"));
        assert_eq!(
            link_local("e2:9d:03:6c:58:23").unwrap().to_string(),
            "fe80::e09d:3ff:fe6c:5823"
        );
    }
}
