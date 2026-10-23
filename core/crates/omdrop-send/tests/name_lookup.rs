//! Port of omdrop-awdl's `tests/test_name_lookup.py`: a name lookup reports
//! each answer as it arrives and asks late arrivals, and a send that waits
//! for a sleeping peer wakes it while it waits. Against a stubbed
//! environment: no radio, no Bluetooth, no subprocesses.

use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, MutexGuard};
use std::time::{Duration, Instant};

/// A test mutex: a panic in one test thread has already failed the test.
#[derive(Default)]
struct Mutex<T>(std::sync::Mutex<T>);

impl<T> Mutex<T> {
    fn new(value: T) -> Self {
        Mutex(std::sync::Mutex::new(value))
    }

    fn lock(&self) -> MutexGuard<'_, T> {
        self.0.lock().expect("a test thread panicked")
    }
}

use omdrop_send::send_to_peer::{Env, main, peer_names};

#[derive(Clone, Debug, PartialEq)]
enum Event {
    WakeUp(f64),
    WakeDown,
    Knock(bool),
    Send,
}

/// A gate the slow peers wait on (5 s cap, as the Python test's Event.wait(5)).
#[derive(Default)]
struct Gate {
    open: Mutex<bool>,
    cv: Condvar,
}

impl Gate {
    fn release(&self) {
        *self.open.lock() = true;
        self.cv.notify_all();
    }

    fn wait(&self) {
        let open = self.open.lock();
        let _ = self
            .cv
            .wait_timeout_while(open, Duration::from_secs(5), |o| !*o);
    }
}

struct Fake {
    t0: Instant,
    /// Seconds per monotonic() call, or 0 for the real clock.
    step: f64,
    calls: AtomicUsize,
    answers: HashMap<String, Option<String>>,
    slow: Vec<String>,
    gate: Arc<Gate>,
    knocks: Mutex<Vec<bool>>,
    events: Mutex<Vec<Event>>,
    peers: Vec<(String, Option<i64>)>,
}

impl Fake {
    fn new() -> Fake {
        Fake {
            t0: Instant::now(),
            step: 0.0,
            calls: AtomicUsize::new(0),
            answers: HashMap::new(),
            slow: Vec::new(),
            gate: Arc::new(Gate::default()),
            knocks: Mutex::new(Vec::new()),
            events: Mutex::new(Vec::new()),
            peers: Vec::new(),
        }
    }

    fn events(&self) -> Vec<Event> {
        self.events.lock().clone()
    }
}

impl Env for Fake {
    fn monotonic(&self) -> f64 {
        if self.step > 0.0 {
            self.calls.fetch_add(1, Ordering::SeqCst) as f64 * self.step
        } else {
            self.t0.elapsed().as_secs_f64()
        }
    }

    fn sleep(&self, _secs: f64) {}

    fn peers(&self) -> Result<Vec<(String, Option<i64>)>, String> {
        Ok(self.peers.clone())
    }

    fn listening(&self, _host: Ipv6Addr, _port: u16, _timeout: f64) -> bool {
        let mut k = self.knocks.lock();
        let opened = if k.is_empty() { false } else { k.remove(0) };
        self.events.lock().push(Event::Knock(opened));
        opened
    }

    fn wake_start(&self, seconds: f64) -> (bool, Option<String>) {
        self.events.lock().push(Event::WakeUp(seconds));
        (true, None)
    }

    fn wake_stop(&self) {
        self.events.lock().push(Event::WakeDown);
    }

    fn peer_name(
        &self,
        mac: &str,
        _port: u16,
        _sender_name: &str,
        _ready_by: Option<f64>,
    ) -> Option<String> {
        if self.slow.iter().any(|m| m == mac) {
            self.gate.wait();
        }
        self.answers.get(mac).cloned().flatten()
    }

    fn sender_command(&self) -> Vec<String> {
        vec!["airdrop-send".into()]
    }

    fn run_sender(&self, _cmd: &[String]) -> i32 {
        self.events.lock().push(Event::Send);
        0
    }

    fn rescan_seconds(&self) -> f64 {
        0.05
    }
}

fn answers(pairs: &[(&str, Option<&str>)]) -> HashMap<String, Option<String>> {
    pairs
        .iter()
        .map(|(m, n)| (m.to_string(), n.map(str::to_owned)))
        .collect()
}

fn macs(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

#[test]
fn an_answer_is_reported_before_a_silent_peer_gives_up() {
    let mut env = Fake::new();
    env.answers = answers(&[("aa", Some("iMac")), ("bb", None)]);
    env.slow = macs(&["bb"]);
    let gate = env.gate.clone();
    let mut seen: Vec<(String, Option<String>)> = Vec::new();
    let mut on_result = |m: &str, n: Option<&str>| {
        seen.push((m.to_owned(), n.map(str::to_owned)));
        if m == "aa" {
            // Only once the fast answer is out does the slow peer finish.
            gate.release();
        }
    };
    let names = peer_names(
        &env,
        &macs(&["aa", "bb"]),
        8770,
        "test",
        true,
        &mut on_result,
        None,
        &mut std::io::sink(),
    );
    assert_eq!(
        seen,
        vec![("aa".into(), Some("iMac".into())), ("bb".into(), None)]
    );
    assert_eq!(
        names,
        vec![("aa".into(), Some("iMac".into())), ("bb".into(), None)]
    );
}

#[test]
fn a_peer_heard_mid_lookup_is_asked_in_the_same_lookup() {
    let mut env = Fake::new();
    env.answers = answers(&[("aa", None), ("cc", Some("Beata's iMac"))]);
    env.slow = macs(&["aa"]);
    let gate = env.gate.clone();
    let mut tables = vec![macs(&["aa"]), macs(&["aa", "cc"])].into_iter();
    let mut rescan = || {
        let table = tables.next().unwrap_or_else(|| macs(&["aa", "cc"]));
        if table.iter().any(|m| m == "cc") {
            let gate = gate.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(200));
                gate.release();
            });
        }
        table
    };
    let names = peer_names(
        &env,
        &macs(&["aa"]),
        8770,
        "test",
        true,
        &mut |_, _| {},
        Some(&mut rescan),
        &mut std::io::sink(),
    );
    let cc = names
        .iter()
        .find(|(m, _)| m == "cc")
        .and_then(|(_, n)| n.clone());
    assert_eq!(cc.as_deref(), Some("Beata's iMac"));
}

#[test]
fn no_newcomers_are_asked_without_a_wake() {
    let mut env = Fake::new();
    env.answers = answers(&[("aa", None), ("cc", Some("late"))]);
    let mut rescan = || macs(&["aa", "cc"]);
    let names = peer_names(
        &env,
        &macs(&["aa"]),
        8770,
        "test",
        false,
        &mut |_, _| {},
        Some(&mut rescan),
        &mut std::io::sink(),
    );
    assert_eq!(names, vec![("aa".into(), None)]);
    assert!(!env.events().contains(&Event::WakeUp(30.0)));
}

const MAC: &str = "7e:49:49:fe:ea:4e";

fn run_send(env: &Fake, argv: &[&str], knocks: &[bool]) -> i32 {
    *env.knocks.lock() = knocks.to_vec();
    let mut args: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
    args.push("file".into());
    main(env, &args, &mut std::io::sink(), &mut std::io::sink())
}

fn send_env() -> Fake {
    let mut env = Fake::new();
    env.peers = vec![(MAC.into(), Some(-40))];
    env
}

#[test]
fn the_wake_is_up_while_waiting_and_down_before_the_transfer() {
    let env = send_env();
    let rc = run_send(&env, &["--wait", "20"], &[false, false, true]);
    assert_eq!(rc, 0);
    let ev = env.events();
    assert_eq!(ev[1], Event::WakeUp(20.0));
    let up = ev.iter().position(|e| *e == Event::WakeUp(20.0)).unwrap();
    let second_knock = ev
        .iter()
        .enumerate()
        .filter(|(_, e)| matches!(e, Event::Knock(_)))
        .nth(1)
        .unwrap()
        .0;
    assert!(up < second_knock);
    let down = ev.iter().position(|e| *e == Event::WakeDown).unwrap();
    let send = ev.iter().position(|e| *e == Event::Send).unwrap();
    assert!(down < send);
}

#[test]
fn a_peer_that_never_opens_still_stops_the_wake() {
    let mut env = send_env();
    env.step = 5.0;
    let rc = run_send(&env, &["--wait", "20"], &[]);
    assert_eq!(rc, 3);
    let ev = env.events();
    assert!(ev.contains(&Event::WakeDown));
    assert!(!ev.contains(&Event::Send));
}

#[test]
fn no_wake_is_raised_with_no_wake_or_a_listening_peer() {
    let env = send_env();
    run_send(&env, &["--wait", "20", "--no-wake"], &[false, true]);
    run_send(&env, &["--wait", "20"], &[true]);
    assert!(!env.events().iter().any(|e| matches!(e, Event::WakeUp(_))));
}

// Beyond the Python file: the listing formats omdrop and the panel parse.

#[test]
fn listing_rows_and_placeholders() {
    let mut env = Fake::new();
    env.peers = vec![
        ("e2:9d:03:6c:58:23".into(), Some(-47)),
        ("fe:63:e6:68:9f:12".into(), None),
        ("16:2f:da:27:3d:76".into(), Some(-3)),
    ];
    env.answers = answers(&[
        ("e2:9d:03:6c:58:23", Some("hume")),
        ("fe:63:e6:68:9f:12", Some("")),
        ("16:2f:da:27:3d:76", None),
    ]);
    let run = |argv: &[&str]| {
        let mut out = Vec::new();
        let rc = main(
            &env,
            &argv.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            &mut out,
            &mut std::io::sink(),
        );
        (rc, String::from_utf8(out).unwrap())
    };
    let (rc, out) = run(&["--list"]);
    assert_eq!(rc, 0);
    assert_eq!(
        out,
        "e2:9d:03:6c:58:23   -47 dBm  [fe80::e09d:3ff:fe6c:5823%awdl0]:8770\n\
         fe:63:e6:68:9f:12     ? dBm  [fe80::fc63:e6ff:fe68:9f12%awdl0]:8770\n\
         16:2f:da:27:3d:76    -3 dBm  [fe80::142f:daff:fe27:3d76%awdl0]:8770\n"
    );
    let (rc, out) = run(&["--list", "-n", "--no-wake"]);
    assert_eq!(rc, 0);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
        lines[0],
        "e2:9d:03:6c:58:23   -47 dBm  [fe80::e09d:3ff:fe6c:5823%awdl0]:8770  hume"
    );
    assert_eq!(
        lines[1],
        "fe:63:e6:68:9f:12     ? dBm  [fe80::fc63:e6ff:fe68:9f12%awdl0]:8770  (anonymous)"
    );
    assert_eq!(
        lines[2],
        "16:2f:da:27:3d:76    -3 dBm  [fe80::142f:daff:fe27:3d76%awdl0]:8770  (no response)"
    );
    let (rc, out) = run(&["--list", "--names", "--stream", "--no-wake"]);
    assert_eq!(rc, 0);
    assert_eq!(out.lines().count(), 3);
    let (rc, out) = run(&[
        "--print",
        "--mac",
        "e2:9d",
        "--name",
        "Study Mac",
        "--",
        "-odd.txt",
    ]);
    assert_eq!(rc, 0);
    assert_eq!(
        out,
        "airdrop-send --direct [fe80::e09d:3ff:fe6c:5823%awdl0]:8770 --op-timeout 60.0 --name Study Mac -- -odd.txt\n"
    );
}

/// A name is whatever the device in range chose. It must not add a row,
/// reach the terminal as a control sequence, or grow a row without bound.
#[test]
fn hostile_peer_names_stay_on_their_own_row() {
    let mut env = Fake::new();
    let macs = [
        "e2:9d:03:6c:58:23",
        "fe:63:e6:68:9f:12",
        "16:2f:da:27:3d:76",
        "0a:1b:2c:3d:4e:5f",
    ];
    env.peers = macs.iter().map(|m| (m.to_string(), Some(-50))).collect();
    let forged = "Evil\n16:2f:da:27:3d:76    -3 dBm  [fe80::1%awdl0]:8770  Boss's iPhone";
    let escapes = "\u{1b}]0;pwned\u{7}\u{1b}[2J\u{9b}31mRed\u{202e}gnp.exe\u{200b}\u{2066}";
    let huge = "x".repeat(1 << 20);
    env.answers = answers(&[
        (macs[0], Some(forged)),
        (macs[1], Some(escapes)),
        (macs[2], Some(huge.as_str())),
        (macs[3], Some(" \u{1b}\u{7}\u{feff}\r\n ")),
    ]);
    for argv in [
        &["--list", "--names", "--no-wake"][..],
        &["--list", "--names", "--stream", "--no-wake"][..],
    ] {
        let mut out = Vec::new();
        let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        assert_eq!(main(&env, &argv, &mut out, &mut std::io::sink()), 0);
        let out = String::from_utf8(out).unwrap();
        let rows: Vec<&str> = out.lines().collect();
        assert_eq!(rows.len(), 4, "{out:?}");
        let name_of = |mac: &str| -> &str {
            let row = rows.iter().find(|r| r.starts_with(mac)).unwrap();
            row.split_once(":8770  ").unwrap().1
        };
        assert_eq!(
            name_of(macs[0]),
            "Evil16:2f:da:27:3d:76    -3 dBm  [fe80::1%awdl0]:8770  Boss's iPhone"
        );
        assert_eq!(name_of(macs[1]), "]0;pwned[2J31mRedgnp.exe");
        assert_eq!(name_of(macs[2]), "x".repeat(255));
        assert_eq!(name_of(macs[3]), "(anonymous)");
        assert!(!out.chars().any(|c| c != '\n' && c.is_control()), "{out:?}");
    }
}

#[test]
fn choosing_a_peer() {
    let mut env = Fake::new();
    // A stepping clock, so the --wait case below does not spin for real seconds.
    env.step = 1.0;
    env.peers = vec![
        ("e2:9d:03:6c:58:23".into(), Some(-47)),
        ("fe:63:e6:68:9f:12".into(), Some(-50)),
    ];
    env.answers = answers(&[
        ("e2:9d:03:6c:58:23", Some("hume")),
        ("fe:63:e6:68:9f:12", Some("f0011")),
    ]);
    let run = |argv: &[&str]| {
        let mut err = Vec::new();
        let rc = main(
            &env,
            &argv.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            &mut std::io::sink(),
            &mut err,
        );
        (rc, String::from_utf8(err).unwrap())
    };
    let (rc, err) = run(&["f"]);
    assert_eq!(rc, 2);
    assert!(
        err.starts_with(
            "several peers heard; choose one with --mac:\n  e2:9d:03:6c:58:23   -47 dBm\n"
        ),
        "{err}"
    );
    // A hex-looking name is a name, not an address fragment.
    let (rc, err) = run(&["--mac", "F0011", "--no-wake", "f"]);
    assert_eq!(rc, 0, "{err}");
    assert!(
        err.contains("sending f to fe:63:e6:68:9f:12 at [fe80::fc63:e6ff:fe68:9f12%awdl0]:8770"),
        "{err}"
    );
    let (rc, err) = run(&["--mac", "nobody", "--no-wake", "f"]);
    assert_eq!(rc, 2);
    assert!(
        err.starts_with(
            "no device answering to \"nobody\" is receiving right now.\n  these named themselves:\n"
        ),
        "{err}"
    );
    let (rc, err) = run(&["--mac", "aa:bb", "f"]);
    assert_eq!(rc, 2);
    assert_eq!(
        err,
        "aa:bb is not in the peer table; --list shows what is\n"
    );
    let (rc, err) = run(&["--mac", ":", "f"]);
    assert_eq!(rc, 2);
    assert!(err.starts_with("\":\" matches more than one device:"));
    let (rc, err) = run(&["--url", "https://x/", "f"]);
    assert_eq!(rc, 2);
    assert!(err.ends_with("send-to-peer: error: send links and files separately: a transfer carries one or the other\n"));
    let (rc, err) = run(&["--mac", "e2:9d", "--wait", "5", "--no-wake", "f"]);
    assert_eq!(rc, 3);
    assert!(
        err.contains("e2:9d:03:6c:58:23 never opened 8770; on an iPhone"),
        "{err}"
    );
}

#[test]
fn an_empty_room_and_a_failed_helper_differ() {
    let env = Fake::new();
    let mut out = Vec::new();
    assert_eq!(
        main(&env, &["--list".to_owned()], &mut out, &mut std::io::sink()),
        1
    );
    assert!(
        String::from_utf8(out)
            .unwrap()
            .starts_with("no devices found: nothing nearby is advertising.")
    );

    struct Broken;
    impl Env for Broken {
        fn monotonic(&self) -> f64 {
            0.0
        }
        fn sleep(&self, _: f64) {}
        fn peers(&self) -> Result<Vec<(String, Option<i64>)>, String> {
            Err("could not read the peer table (x exited 1): no".into())
        }
        fn listening(&self, _: Ipv6Addr, _: u16, _: f64) -> bool {
            false
        }
        fn wake_start(&self, _: f64) -> (bool, Option<String>) {
            (false, None)
        }
        fn wake_stop(&self) {}
        fn peer_name(&self, _: &str, _: u16, _: &str, _: Option<f64>) -> Option<String> {
            None
        }
        fn sender_command(&self) -> Vec<String> {
            Vec::new()
        }
        fn run_sender(&self, _: &[String]) -> i32 {
            0
        }
    }
    let mut err = Vec::new();
    assert_eq!(
        main(
            &Broken,
            &["--list".to_owned()],
            &mut std::io::sink(),
            &mut err
        ),
        4
    );
    assert_eq!(
        String::from_utf8(err).unwrap(),
        "could not read the peer table (x exited 1): no\n"
    );
}
