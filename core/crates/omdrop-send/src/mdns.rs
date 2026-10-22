//! Browse `_airdrop._tcp.local` over IPv6 on one interface: a minimal,
//! bounded mDNS querier (RFC 6762) in place of python-zeroconf.
//!
//! Only what airdrop-send.py's browser used: each instance that appears is
//! resolved (SRV, TXT, AAAA) and handed to the caller once; removals and
//! updates are ignored, and an instance that does not resolve within 3 s
//! (zeroconf's `get_service_info` default) is dropped. Packets are accepted
//! only from link-local sources on the browsed interface, and every name and
//! record is bounds-checked: this is untrusted network input. So are the
//! tables: at most 256 instances resolve at once, the oldest giving way to a
//! newcomer, an address is kept only for a host an unresolved instance
//! names, and of a finished instance only the name of one handed to the
//! caller is kept, so it is not handed over twice.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};

const MDNS_GROUP: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
const MDNS_PORT: u16 = 5353;
pub const SERVICE: &str = "_airdrop._tcp.local";
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(3);
const T_A: u16 = 1;
const T_PTR: u16 = 12;
const T_TXT: u16 = 16;
const T_AAAA: u16 = 28;
const T_SRV: u16 = 33;
/// Instances resolving at once. A room holds a handful of AirDrop devices;
/// past this, the oldest unresolved instance makes way for a new one, so a
/// flood of made-up names costs memory for 256 and never shuts a real
/// receiver out: one answers PTR, SRV, TXT and AAAA together and resolves
/// as soon as it is taken on.
const MAX_INSTANCES: usize = 256;
/// Names of instances already handed to the caller, so one is not handed
/// over again when it answers the next browse query. The oldest are
/// forgotten past this; at worst one is then handed over twice.
const MAX_HANDED: usize = 1024;

/// A resolved `_airdrop._tcp` instance.
#[derive(Clone, Debug, PartialEq)]
pub struct Found {
    /// The full instance name, `0e9d036c5823._airdrop._tcp.local.`.
    pub name: String,
    /// The SRV target, `hume.local.`.
    pub server: String,
    pub port: u16,
    pub addrs: Vec<Ipv6Addr>,
    /// TXT `key=value` pairs; keys without a value are dropped, as Python's
    /// properties comprehension dropped them.
    pub props: Vec<(String, String)>,
}

#[derive(Default)]
struct Instance {
    display: String,
    srv: Option<(u16, String)>,
    txt: Option<Vec<(String, String)>>,
    first_seen: Option<Instant>,
    last_query: Option<Instant>,
    done: bool,
    /// Order taken on, for making way for a newcomer.
    seq: u64,
}

/// What a browse has heard: instances still resolving, the addresses of the
/// hosts they name, and the names of those handed to the caller. An instance
/// that gave up is forgotten, and taken on again if it answers again.
#[derive(Default)]
struct Tables {
    instances: HashMap<String, Instance>,
    hosts: HashMap<String, Vec<Ipv6Addr>>,
    handed: HashSet<String>,
    handed_order: VecDeque<String>,
    next_seq: u64,
}

impl Tables {
    /// Take on the instance a PTR names, unless it is already resolving or
    /// was handed to the caller, making way if the table is full.
    fn admit(&mut self, target: &str) {
        let key = target.to_ascii_lowercase();
        if self.instances.contains_key(&key) || self.handed.contains(&key) {
            return;
        }
        if self.instances.len() >= MAX_INSTANCES
            && let Some(oldest) = self
                .instances
                .iter()
                .min_by_key(|(_, i)| i.seq)
                .map(|(k, _)| k.clone())
        {
            self.instances.remove(&oldest);
        }
        self.next_seq += 1;
        self.instances.insert(
            key,
            Instance {
                display: target.to_owned(),
                seq: self.next_seq,
                ..Instance::default()
            },
        );
    }

    /// Each unresolved instance that now has its SRV, TXT and an address,
    /// marked done and remembered as handed over.
    fn take_resolved(&mut self) -> Vec<Found> {
        let mut found = Vec::new();
        for (key, inst) in self.instances.iter_mut().filter(|(_, i)| !i.done) {
            let (Some((port, server)), Some(txt)) = (&inst.srv, &inst.txt) else {
                continue;
            };
            let Some(addrs) = self
                .hosts
                .get(&server.to_ascii_lowercase())
                .filter(|a| !a.is_empty())
            else {
                continue;
            };
            inst.done = true;
            if self.handed.insert(key.clone()) {
                self.handed_order.push_back(key.clone());
                if self.handed_order.len() > MAX_HANDED
                    && let Some(old) = self.handed_order.pop_front()
                {
                    self.handed.remove(&old);
                }
            }
            found.push(Found {
                name: format!("{}.", inst.display),
                server: format!("{server}."),
                port: *port,
                addrs: addrs.clone(),
                props: txt.clone(),
            });
        }
        found
    }

    /// Drop the instances that resolved or gave up, and the addresses no
    /// unresolved instance needs.
    fn retire(&mut self) {
        self.instances.retain(|_, inst| !inst.done);
        let wanted: HashSet<String> = self
            .instances
            .values()
            .filter_map(|i| i.srv.as_ref())
            .map(|(_, target)| target.to_ascii_lowercase())
            .collect();
        self.hosts.retain(|host, _| wanted.contains(host));
    }
}

/// The browsing socket on one interface.
pub struct Browser {
    sock: UdpSocket,
    ifindex: u32,
    /// The interface's first IPv6 address (logged).
    pub ip_addr: Ipv6Addr,
}

impl Browser {
    /// Join ff02::fb on `iface`. Fails when the interface has no IPv6
    /// address, as the zeroconf browser did.
    pub fn new(iface: &str) -> io::Result<Browser> {
        let ip_addr = omdrop_proto::net::interface_ipv6(iface).ok_or_else(|| {
            io::Error::other(format!("Interface {iface} does not have an IPv6 address"))
        })?;
        let ifindex = omdrop_proto::net::scope_id(iface)?;
        let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        sock.set_only_v6(true)?;
        sock.set_reuse_address(true)?;
        sock.set_reuse_port(true)?;
        // Port 5353 hears multicast answers; if another responder holds it
        // without SO_REUSEPORT, an ephemeral port still gets the unicast
        // replies RFC 6762 6.7 sends to legacy queriers.
        let any = |port| SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0));
        if sock.bind(&any(MDNS_PORT).into()).is_err() {
            sock.bind(&any(0).into())?;
        }
        sock.join_multicast_v6(&MDNS_GROUP, ifindex)?;
        sock.set_multicast_if_v6(ifindex)?;
        sock.set_multicast_hops_v6(255)?;
        sock.set_multicast_loop_v6(false)?;
        Ok(Browser {
            sock: sock.into(),
            ifindex,
            ip_addr,
        })
    }

    fn send_query(&self, questions: &[(&str, u16)]) {
        let msg = query(questions);
        let dest = SocketAddrV6::new(MDNS_GROUP, MDNS_PORT, 0, self.ifindex);
        // A lost query is retried on the next round.
        let _ = self.sock.send_to(&msg, dest);
    }

    /// Browse until `deadline`, calling `on_found` once per resolved
    /// instance, in the order they resolve. `on_found` returns true to stop.
    /// It runs on this thread, as zeroconf's handler ran on its browser
    /// thread, so it should bound its own work by the same deadline.
    pub fn browse(
        &self,
        deadline: Instant,
        mut on_found: impl FnMut(Found) -> bool,
    ) -> io::Result<()> {
        let mut tables = Tables::default();
        let mut next_browse = Instant::now();
        let mut interval = Duration::from_secs(1);
        let mut buf = vec![0u8; 9000];
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Ok(());
            }
            if now >= next_browse {
                self.send_query(&[(SERVICE, T_PTR)]);
                next_browse = now + interval;
                interval = (interval * 2).min(Duration::from_secs(20));
            }
            // Ask for what an instance still lacks, once a second, until it
            // resolves or gives up.
            let mut wake = next_browse.min(deadline);
            for inst in tables.instances.values_mut().filter(|i| !i.done) {
                let first = *inst.first_seen.get_or_insert(now);
                if now.duration_since(first) >= RESOLVE_TIMEOUT {
                    inst.done = true;
                    continue;
                }
                if inst
                    .last_query
                    .is_none_or(|t| now.duration_since(t) >= Duration::from_secs(1))
                {
                    let mut qs: Vec<(&str, u16)> = Vec::new();
                    if inst.srv.is_none() {
                        qs.push((&inst.display, T_SRV));
                    }
                    if inst.txt.is_none() {
                        qs.push((&inst.display, T_TXT));
                    }
                    if let Some((_, target)) = &inst.srv
                        && !tables.hosts.contains_key(&target.to_ascii_lowercase())
                    {
                        qs.push((target, T_AAAA));
                    }
                    if !qs.is_empty() {
                        self.send_query(&qs);
                    }
                    inst.last_query = Some(now);
                }
                wake = wake
                    .min(inst.last_query.unwrap_or(now) + Duration::from_secs(1))
                    .min(first + RESOLVE_TIMEOUT);
            }
            let wait = wake
                .saturating_duration_since(Instant::now())
                .max(Duration::from_millis(10));
            self.sock.set_read_timeout(Some(wait))?;
            match self.sock.recv_from(&mut buf) {
                Ok((n, SocketAddr::V6(src))) => {
                    // Only link-local peers on this interface.
                    if src.ip().is_unicast_link_local()
                        && src.scope_id() == self.ifindex
                        && let Some(records) = buf.get(..n).and_then(parse_message)
                    {
                        absorb(records, &mut tables);
                    }
                }
                Ok(_) => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e),
            }
            for found in tables.take_resolved() {
                if on_found(found) {
                    return Ok(());
                }
                if Instant::now() >= deadline {
                    return Ok(());
                }
            }
            tables.retire();
        }
    }
}

fn absorb(records: Vec<Rr>, tables: &mut Tables) {
    // PTRs first so an answer carrying PTR, SRV and TXT together resolves at once.
    for rr in &records {
        if let RData::Ptr(target) = &rr.data
            && rr.ttl > 0
            && rr.name.eq_ignore_ascii_case(SERVICE)
        {
            tables.admit(target);
        }
    }
    // Then SRV and TXT, so an AAAA in the same answer finds the host named.
    let mut addresses = Vec::new();
    for rr in records {
        if rr.ttl == 0 {
            continue;
        }
        let key = rr.name.to_ascii_lowercase();
        match rr.data {
            RData::Srv(port, target) => {
                if let Some(inst) = tables.instances.get_mut(&key) {
                    inst.srv = Some((port, target));
                }
            }
            RData::Txt(entries) => {
                if let Some(inst) = tables.instances.get_mut(&key) {
                    inst.txt = Some(entries);
                }
            }
            RData::Aaaa(addr) => addresses.push((key, addr)),
            RData::Ptr(_) | RData::Other => {}
        }
    }
    // Only for a host an unresolved instance names: anything else is noise,
    // and an instance still lacking its address asks for it.
    let wanted: HashSet<String> = tables
        .instances
        .values()
        .filter(|i| !i.done)
        .filter_map(|i| i.srv.as_ref())
        .map(|(_, target)| target.to_ascii_lowercase())
        .collect();
    let mut seen_aaaa: HashSet<String> = HashSet::new();
    for (key, addr) in addresses {
        if !wanted.contains(&key) {
            continue;
        }
        let list = tables.hosts.entry(key.clone()).or_default();
        // A fresh answer replaces the cached set rather than growing it forever.
        if seen_aaaa.insert(key) {
            list.clear();
        }
        if !list.contains(&addr) && list.len() < 16 {
            list.push(addr);
        }
    }
}

fn encode_name(out: &mut Vec<u8>, name: &str) {
    for label in name.trim_end_matches('.').split('.') {
        let bytes = label.as_bytes();
        let n = bytes.len().min(63);
        out.push(n as u8);
        out.extend_from_slice(bytes.get(..n).unwrap_or_default());
    }
    out.push(0);
}

/// A standard query (id 0, QM) for `questions`.
fn query(questions: &[(&str, u16)]) -> Vec<u8> {
    let mut msg = vec![0, 0, 0, 0];
    msg.extend_from_slice(&(questions.len() as u16).to_be_bytes());
    msg.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    for (name, qtype) in questions {
        encode_name(&mut msg, name);
        msg.extend_from_slice(&qtype.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
    }
    msg
}

#[derive(Debug, PartialEq)]
enum RData {
    Ptr(String),
    Srv(u16, String),
    Txt(Vec<(String, String)>),
    Aaaa(Ipv6Addr),
    Other,
}

#[derive(Debug, PartialEq)]
struct Rr {
    name: String,
    ttl: u32,
    data: RData,
}

fn be16(msg: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*msg.get(off)?, *msg.get(off + 1)?]))
}

/// A (possibly compressed) name at `off`: (name without trailing dot, offset
/// after it in the original position).
fn read_name(msg: &[u8], mut off: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end = None;
    let mut jumps = 0;
    let mut total = 0usize;
    loop {
        let len = *msg.get(off)?;
        match len & 0xc0 {
            0x00 if len == 0 => {
                return Some((labels.join("."), end.unwrap_or(off + 1)));
            }
            0x00 => {
                let label = msg.get(off + 1..off + 1 + len as usize)?;
                total += label.len() + 1;
                if total > 255 {
                    return None;
                }
                labels.push(String::from_utf8_lossy(label).into_owned());
                off += 1 + len as usize;
            }
            0xc0 => {
                let ptr = (be16(msg, off)? & 0x3fff) as usize;
                if end.is_none() {
                    end = Some(off + 2);
                }
                jumps += 1;
                if jumps > 32 || ptr >= msg.len() {
                    return None;
                }
                off = ptr;
            }
            _ => return None,
        }
    }
}

/// Every resource record in a response (answers, authority, additional).
fn parse_message(msg: &[u8]) -> Option<Vec<Rr>> {
    let flags = be16(msg, 2)?;
    if flags & 0x8000 == 0 {
        return None; // a query, not a response
    }
    let qd = be16(msg, 4)? as usize;
    let rr_count = be16(msg, 6)? as usize + be16(msg, 8)? as usize + be16(msg, 10)? as usize;
    let mut off = 12;
    for _ in 0..qd {
        let (_, next) = read_name(msg, off)?;
        off = next + 4;
    }
    let mut out = Vec::new();
    for _ in 0..rr_count {
        let (name, next) = read_name(msg, off)?;
        let rtype = be16(msg, next)?;
        let ttl = u32::from_be_bytes(msg.get(next + 4..next + 8)?.try_into().ok()?);
        let rdlen = be16(msg, next + 8)? as usize;
        let start = next + 10;
        let rdata = msg.get(start..start + rdlen)?;
        let data = match rtype {
            T_PTR => RData::Ptr(read_name(msg, start)?.0),
            T_SRV if rdlen >= 6 => RData::Srv(be16(msg, start + 4)?, read_name(msg, start + 6)?.0),
            T_TXT => {
                let mut entries = Vec::new();
                let mut j = 0;
                while let Some(&l) = rdata.get(j) {
                    let s = rdata.get(j + 1..j + 1 + l as usize)?;
                    if let Some(eq) = s.iter().position(|&c| c == b'=') {
                        let k =
                            String::from_utf8_lossy(s.get(..eq).unwrap_or_default()).into_owned();
                        let v = String::from_utf8_lossy(s.get(eq + 1..).unwrap_or_default())
                            .into_owned();
                        entries.push((k, v));
                    }
                    j += 1 + l as usize;
                }
                RData::Txt(entries)
            }
            T_AAAA if rdlen == 16 => {
                let octets: [u8; 16] = rdata.try_into().ok()?;
                RData::Aaaa(Ipv6Addr::from(octets))
            }
            T_A => RData::Other,
            _ => RData::Other,
        };
        out.push(Rr { name, ttl, data });
        off = start + rdlen;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rr(out: &mut Vec<u8>, name: &str, rtype: u16, ttl: u32, rdata: &[u8]) {
        encode_name(out, name);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&0x8001u16.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(rdata);
    }

    fn answer() -> Vec<u8> {
        let mut msg = vec![0, 0, 0x84, 0, 0, 0, 0, 4, 0, 0, 0, 0];
        let mut ptr = Vec::new();
        encode_name(&mut ptr, "0e9d036c5823._airdrop._tcp.local");
        rr(&mut msg, SERVICE, T_PTR, 4500, &ptr);
        let mut srv = vec![0, 0, 0, 0, 0x22, 0x42];
        encode_name(&mut srv, "hume.local");
        rr(
            &mut msg,
            "0e9d036c5823._airdrop._tcp.local",
            T_SRV,
            120,
            &srv,
        );
        rr(
            &mut msg,
            "0e9d036c5823._airdrop._tcp.local",
            T_TXT,
            4500,
            b"\x09flags=987\x04bare",
        );
        let ip: Ipv6Addr = "fe80::e09d:3ff:fe6c:5823".parse().unwrap();
        rr(&mut msg, "hume.local", T_AAAA, 120, &ip.octets());
        msg
    }

    #[test]
    fn an_answer_resolves_an_instance() {
        let records = parse_message(&answer()).unwrap();
        let mut tables = Tables::default();
        absorb(records, &mut tables);
        let inst = &tables.instances["0e9d036c5823._airdrop._tcp.local"];
        assert_eq!(inst.srv, Some((8770, "hume.local".to_owned())));
        assert_eq!(inst.txt, Some(vec![("flags".to_owned(), "987".to_owned())]));
        assert_eq!(
            tables.hosts["hume.local"],
            vec!["fe80::e09d:3ff:fe6c:5823".parse::<Ipv6Addr>().unwrap()]
        );
    }

    fn record(name: &str, data: RData) -> Rr {
        Rr {
            name: name.to_owned(),
            ttl: 120,
            data,
        }
    }

    fn ptrs(names: impl Iterator<Item = String>) -> Vec<Rr> {
        names.map(|n| record(SERVICE, RData::Ptr(n))).collect()
    }

    fn fakes(batch: usize) -> Vec<Rr> {
        ptrs((0..MAX_INSTANCES).map(|i| format!("fake{batch}-{i}._airdrop._tcp.local")))
    }

    /// What the browse loop does after each packet: hand over what resolved,
    /// then retire what is done.
    fn after_packet(tables: &mut Tables) -> Vec<String> {
        let found = tables.take_resolved().into_iter().map(|f| f.name).collect();
        tables.retire();
        found
    }

    /// Anything on the link can answer with made-up instances and hosts, a
    /// few hundred per packet, for as long as the browse lasts.
    #[test]
    fn a_flood_of_names_is_bounded() {
        let ip: Ipv6Addr = "fe80::1".parse().unwrap();
        let mut tables = Tables::default();
        for batch in 0..4 {
            absorb(fakes(batch), &mut tables);
            absorb(
                (0..MAX_INSTANCES)
                    .map(|i| record(&format!("host{batch}-{i}.local"), RData::Aaaa(ip)))
                    .collect(),
                &mut tables,
            );
        }
        assert_eq!(tables.instances.len(), MAX_INSTANCES);
        // The newest stay.
        assert!(tables.instances.contains_key("fake3-0._airdrop._tcp.local"));
        // No instance names those hosts.
        assert!(tables.hosts.is_empty());
        // An address in the same answer as the SRV naming it is kept, in
        // whatever order the records come.
        let inst = tables.instances.keys().next().unwrap().clone();
        absorb(
            vec![
                record("a.local", RData::Aaaa(ip)),
                record(&inst, RData::Srv(8770, "A.local".into())),
            ],
            &mut tables,
        );
        assert_eq!(tables.hosts["a.local"], vec![ip]);
        // Instances that gave up are forgotten, with their addresses.
        for i in tables.instances.values_mut() {
            i.done = true;
        }
        tables.retire();
        assert!(tables.instances.is_empty());
        assert!(tables.hosts.is_empty());
        assert!(tables.handed.is_empty());
    }

    /// A flood of names that never resolve, timing out batch after batch or
    /// still resolving, must not keep a real receiver from being found.
    #[test]
    fn a_real_receiver_is_found_through_a_flood_of_names() {
        let real = "0e9d036c5823._airdrop._tcp.local.";
        let mut tables = Tables::default();
        // Over 1024 names, each batch timing out.
        for batch in 0..5 {
            absorb(fakes(batch), &mut tables);
            assert!(after_packet(&mut tables).is_empty());
            for i in tables.instances.values_mut() {
                i.done = true;
            }
            tables.retire();
        }
        // And a table full of names still resolving.
        absorb(fakes(5), &mut tables);
        assert_eq!(tables.instances.len(), MAX_INSTANCES);
        absorb(parse_message(&answer()).unwrap(), &mut tables);
        assert_eq!(after_packet(&mut tables), [real]);
        assert!(tables.instances.len() < MAX_INSTANCES);
        // Handed over once: its answer to the next browse query is ignored.
        absorb(parse_message(&answer()).unwrap(), &mut tables);
        assert!(after_packet(&mut tables).is_empty());
        // Only so many handed-over names are kept: the oldest go first.
        for batch in 0..5 {
            for name in (0..MAX_INSTANCES).map(|i| format!("r{batch}-{i}._airdrop._tcp.local")) {
                tables.admit(&name);
                let inst = tables.instances.get_mut(&name).unwrap();
                inst.srv = Some((8770, "h.local".into()));
                inst.txt = Some(Vec::new());
            }
            tables
                .hosts
                .insert("h.local".into(), vec!["fe80::1".parse().unwrap()]);
            assert_eq!(after_packet(&mut tables).len(), MAX_INSTANCES);
        }
        assert_eq!(tables.handed.len(), MAX_HANDED);
        assert_eq!(tables.handed_order.len(), MAX_HANDED);
        assert!(!tables.handed.contains("0e9d036c5823._airdrop._tcp.local"));
    }

    #[test]
    fn compression_loops_and_truncation_are_refused() {
        // A pointer to itself.
        let mut msg = vec![0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0xc0, 12];
        msg.extend_from_slice(&[0, 12, 0, 1, 0, 0, 0, 1, 0, 0]);
        assert_eq!(parse_message(&msg), None);
        let full = answer();
        for cut in 0..full.len() {
            let _ = parse_message(&full[..cut]);
        }
        // Queries are not answers.
        assert_eq!(parse_message(&query(&[(SERVICE, T_PTR)])), None);
    }

    #[test]
    fn queries_encode_names() {
        let q = query(&[(SERVICE, T_PTR)]);
        assert_eq!(&q[4..6], &[0, 1]);
        assert_eq!(read_name(&q, 12).unwrap().0, SERVICE);
    }
}
