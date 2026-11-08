//! omdrop -- send and receive files with nearby Apple devices.
//!
//! "omdrop" is this project's name for the feature. The protocol it speaks
//! is Apple's, and its wire identifiers are not ours to rename: the service
//! is _airdrop._tcp, the endpoints are /Discover, /Ask and /Upload, and the
//! receiver's config is ~/.config/airdrop/config.toml -- protocol- and
//! service-layer names, not product ones.
//!
//! The panel holds no state of its own. It shells out to this command for
//! every action and reads `omdrop status --json`, `peers --json` and
//! `peers --json -n --stream`, whose bytes are unchanged from the bash
//! version this replaces, as is every subcommand, message and exit status.

#[macro_use]
mod util;
mod config;
mod ctx;
mod driver;
mod identity;
mod links;
mod pick;
mod proc;
mod send;
mod status;
mod window;

use std::ffi::OsString;
use std::io::Write;
use std::path::Path;

use crate::ctx::ctx;

const USAGE: &str = r#"omdrop -- send and receive files with nearby Apple devices

  on [-c|-e] [DURATION]
                    become visible to nearby Apple devices and receive files.
                    Stops again after DURATION (default 10m). A bare number
                    is minutes, so "on 3" is three minutes; "10m", "1h" and
                    "30s" also work. "forever" stays on until you turn it
                    off; "once" stops after the first file arrives.
                    -e/--everyone  anyone nearby may send (the default)
                    -c/--contacts  only known senders may send
                    Either flag also sets the saved visibility, so it stays
                    that way until you change it back.
  off [--force]     stop receiving and advertising, cancel any pending window.
                    Refuses while a send is running, since that would cut it
                    off; --force stops anyway
  toggle            off if receiving, on if not
  status [--json]   receiving or not, time left, the name Macs see
  send [NAME] FILE...|URL...
                    send files to a nearby Apple device, as one transfer
                    it accepts once, or send http/https links. A .webloc or
                    .url file holding a web link goes as that link.
                    Send links and files separately. With Omdrop off, a
                    send to NAME turns it on for the usual window first.
                    NAME searches for up to two minutes, reporting devices
                    as they answer; OMDROP_NAME_WAIT sets this in seconds.
                    An exact name wins over a partial match; duplicate names
                    need --to ADDRESS. Cleanup can take two more seconds.
                    --wait SECONDS waits for an iPhone's receiver to wake
                    (default 30), separately from finding its name, announcing
                    this machine over Bluetooth. --pick opens a file chooser.
  peers [-n]        the Apple devices nearby right now. -n also asks
                    each one for its name, which means connecting to it and
                    showing this machine to every device listed, and briefly
                    announcing this Apple ID over Bluetooth so a "Contacts
                    Only" device will answer at all. --no-wake skips the
                    announcement; names then come only from devices that are
                    already listening. --json prints one JSON array
  name [NEW]        show the name, or set it (restarts a running receiver)
  dir [PATH|--pick] show the download folder, or set it (--pick: in a chooser)
  sound [on|off]    the panel's radar sound effects
  limit [PERCENT]   show the maximum transfer size, or set it to 1-90% of
                    currently free space (default 30%)
  receive-mode [MODE] show, or set to "auto" (default) or "ask".
  visibility [MODE]  show, or set to "everyone" (default) or "contacts".
                     In contacts mode only known senders may send to you.
  senders [add|remove ID | list]
                     manage the known-senders list (emails and phone numbers)
  identity [status|unlock|lock]
                    which identity Apple devices see. With the identity in
                    1Password, `unlock` fetches it now and `lock` turns
                    Omdrop off and clears the cached copy.
  identity 1password import [--vault V] [--title T]
                    move the Apple identity from ~/.omdrop/keys into
                    1Password; the files are deleted only once 1Password
                    holds an identical copy
  identity 1password use ITEM | off
                    use an identity already in 1Password, or stop using it
  setup             install what receiving needs: the service, the name Macs
                    see, this computer's certificate, and the handler that
                    opens received links on double-click. Safe to run again.
  doctor [--json]   what is still missing before this can receive
  install-driver    build and install the Wi-Fi driver, in a terminal you watch
  install-core      install omdrop-core, the Rust version of Omdrop, built from
                    this plugin, in a terminal you watch
  firewall ACTION   install or remove Omdrop's narrow UFW receiver rule
  links ACTION      install or remove the double-click handler for received
                    .url and .webloc links
  open-link FILE    open a .url or .webloc link in the browser (web links only)
  skill ACTION      install or remove the skill that tells AI agents how to
                    use omdrop (nothing else installs it)
  version           the plugin version, for bug reports

Aliases, if you reach for a different word:
  start = on      stop = off      list = peers      vis, viz = visibility

Examples:
  omdrop on 10m
  omdrop on forever
  omdrop send ~/photo.jpg
  omdrop send "Studio Mac" https://omarchy.org/
  omdrop name "Brent's Omarchy"
  omdrop limit 30
"#;

/// The versions a bug report needs: the plugin's, from the manifest the
/// marketplace reads, and this program's. A plugin that cannot be found is
/// said out loud rather than guessed at.
fn cmd_version() -> i32 {
    let core = env!("CARGO_PKG_VERSION");
    let plugin = ctx().plugin_dir().map(Path::to_path_buf);
    let version = plugin.as_ref().and_then(|dir| {
        let text = std::fs::read(dir.join("manifest.json")).ok()?;
        let v: serde_json::Value = serde_json::from_slice(&text).ok()?;
        v.get("version")?.as_str().map(str::to_string)
    });
    match (plugin, version) {
        (_, Some(v)) => outln!("omdrop {v}"),
        (Some(dir), None) => errln!(
            "omdrop: could not read a version from {}/manifest.json.",
            dir.display()
        ),
        (None, None) => {
            errln!("omdrop: no Omdrop plugin was found, so only this program's version is known.")
        }
    }
    outln!("omdrop-core {core}");
    0
}

fn strings(args: &[OsString]) -> Vec<String> {
    args.iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect()
}

fn main() {
    if let Err(e) = ctx::implementation() {
        eprintln!("omdrop: {e}");
        std::process::exit(2);
    }
    let argv: Vec<OsString> = std::env::args_os().skip(1).collect();
    let cmd = argv
        .first()
        .map(|a| a.to_string_lossy().into_owned())
        .unwrap_or_else(|| "status".to_string());
    let rest = argv.get(1..).unwrap_or(&[]);
    let s = strings(rest);
    // Aliases exist because the words are guessable but not memorable:
    // someone who has used systemctl reaches for start/stop, and someone who
    // has used a peer tool reaches for list.
    let code = match cmd.as_str() {
        "on" | "start" => window::cmd_on(&s),
        "off" | "stop" => window::cmd_off(&s),
        "toggle" => window::cmd_toggle(&s),
        "status" => status::cmd_status(&s),
        "send" => send::cmd_send(rest),
        "peers" | "list" => send::cmd_peers(&s),
        "name" => status::cmd_name(&s),
        "dir" => status::cmd_dir(&s),
        "sound" => status::cmd_sound(&s),
        "limit" => status::cmd_limit(&s),
        "receive-mode" => status::cmd_receive_mode(&s),
        "visibility" | "vis" | "viz" => status::cmd_visibility(&s),
        "senders" => status::cmd_senders(&s),
        "identity" => identity::cmd_identity(&s),
        "setup" => window::cmd_setup(),
        "doctor" => driver::cmd_doctor(&s),
        "links" => links::cmd_links(&s),
        "skill" | "skills" => links::cmd_skill(&s),
        "open-link" => links::cmd_open_link(rest),
        "install-driver" => driver::cmd_install_driver(),
        "install-core" => driver::cmd_install_core(),
        "firewall" => driver::cmd_firewall(&s),
        "act" => links::cmd_act(rest),
        "watch" => links::cmd_watch(&s),
        "resume" => window::cmd_resume(),
        "handle" => links::cmd_handle(rest),
        identity::IDENTITY_SUBCOMMAND => identity::cmd_identity_child(&s),
        "-V" | "--version" | "version" => cmd_version(),
        "-h" | "--help" | "help" => {
            let _ = std::io::stdout().write_all(USAGE.as_bytes());
            0
        }
        _ => {
            let _ = std::io::stderr().write_all(USAGE.as_bytes());
            1
        }
    };
    util::exit(code)
}
