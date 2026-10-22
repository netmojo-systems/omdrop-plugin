//! The name a peer answers /Discover with is cleaned before anything shows
//! it: `airdrop-send` logs it and send-to-peer lists it. Loopback TLS only.

mod common;

use common::*;
use omdrop_send::airdrop_send::{parse_options, sender_from_identity};
use omdrop_send::client::Client;
use omdrop_send::http::Endpoint;
use omdrop_send::log::{Logger, Sink};

fn discover(answer_name: &str) -> Option<String> {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = pair(dir.path(), "peer");
    let server = identity(&cert, &key, None);
    let (port, handle) = one_shot(&server, name_answer(answer_name));
    let opts = parse_options(&[
        "--discover-only".into(),
        "--direct".into(),
        format!("127.0.0.1:{port}"),
        "--op-timeout".into(),
        "5".into(),
    ])
    .unwrap();
    let sender =
        sender_from_identity(&identity(&cert, &key, None), &opts, "020000000001".into()).unwrap();
    let log = Logger::new(Sink::Silent);
    let mut client = Client::new(
        &sender,
        Endpoint::resolve("127.0.0.1", port, "lo").unwrap(),
        &log,
    );
    let name = client.discover().unwrap();
    handle.join().unwrap();
    name
}

#[test]
fn a_discovered_name_cannot_forge_rows_drive_the_terminal_or_grow_unbounded() {
    assert_eq!(
        discover("Evil\nfe:63:e6:68:9f:12     ? dBm  [fe80::1%awdl0]:8770  Boss").as_deref(),
        Some("Evilfe:63:e6:68:9f:12     ? dBm  [fe80::1%awdl0]:8770  Boss")
    );
    assert_eq!(
        discover("\u{1b}[2J\u{1b}]8;;https://x.example/\u{7}Mac\u{202e}\u{feff}").as_deref(),
        Some("[2J]8;;https://x.example/Mac")
    );
    let huge = format!("{}\u{e9}", "x".repeat(254)) + &"y".repeat((1 << 20) - 256);
    assert_eq!(discover(&huge), Some("x".repeat(254)));
    // Nothing left is no name at all, as when none was offered.
    assert_eq!(discover(" \u{200b}\u{2028}\t "), None);
}
