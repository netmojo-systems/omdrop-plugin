//! What is still missing before this can receive (`doctor`, `setup`'s
//! closing list), installing the driver in a terminal the person watches,
//! and the one firewall rule Omdrop needs.

use std::cmp::Ordering;
use std::path::Path;
use std::process::Command;
use std::sync::LazyLock;
use std::time::Instant;

use serde::Serialize;
use serde_json::{Map, Value};

use crate::ctx::ctx;
use crate::identity::{Out, id};
use crate::proc::{Captured, capture, capture_bounded, run, run_quiet, timeout_duration};
use crate::util::{
    die, env_nonempty, have, home, is_executable, py_json, shell_quote, strip_trailing_newlines,
};

const DRIVER_REPO: &str = "https://github.com/netmojo-systems/omdrop-awdl.git";
/// The package name a repository would carry it under, and the fallback source.
pub const DRIVER_PKG: &str = "brcmfmac-awdl-dkms";
/// The exact driver commit this release builds: the full 40 characters,
/// because a short SHA is not a pin, and a branch would let the built source
/// drift away from what anyone reviewed. It also appears literally in the
/// build script below, because a baseline scanner cannot resolve a variable;
/// a test keeps the two equal.
pub const DRIVER_COMMIT: &str = "e7891ab56957dde46f134c1991e4e4717f94d2e4";
/// The package version that commit builds. install-driver rebuilds any older
/// installed driver: a fix inside the helper changes nothing a feature probe
/// could see.
const DRIVER_VERSION: &str = "0.10.0";
/// The first driver whose sender, send-to-peer and advertiser follow the
/// identity contract. Moving the identity into 1Password needs it.
const DRIVER_IDENTITY_VERSION: &str = "0.7.0";
/// The Python receiver's one outside import, and the kernel keyring library
/// it reads the 1Password identity cache through.
const RECEIVER_PKGS: &str = "python-libarchive-c keyutils";

/// The oldest omdrop-awdl helper contract this works with, for every backend
/// that probes. 0.7.0 is the first whose sender, send-to-peer and advertiser
/// follow the identity contract. Newer features are found by asking the
/// sender (`--help`), not by version.
const BACKEND_CONTRACT_MIN: &str = "0.7.0";
/// Item IDs Omdrop reports itself, and the panel acts on. A backend's own
/// item under one of these names is passed on as backend-<id>, so its
/// sentence still shows but no button offers a fix that cannot fix it.
const PLUGIN_ITEM_IDS: [&str; 4] = ["driver", "library", "service", "firewall"];
/// A probe is a few hundred bytes; anything past this is not an answer.
const PROBE_MAX: usize = 1 << 20;

/// The first and only finding on a machine the Broadcom driver cannot help.
const NO_BROADCOM: &str = "This computer has no Apple Broadcom Wi-Fi, which Omdrop's own driver needs: it runs only on Apple Silicon Macs, not in a virtual machine. Other Wi-Fi cards need a different radio backend (docs/radio-backend.md).";
const LAUNCHER: &str = "omarchy-launch-floating-terminal-with-presentation";

/// UFW's default-drop policy sees AirDrop's TCP after the AWDL data path has
/// done its job, so a healthy radio can advertise while every SYN is
/// discarded. This is the only exception Omdrop needs: IPv6 link-local
/// peers, to our link-local address, on awdl0, TCP 8771.
const UFW_RULE: [&str; 14] = [
    "allow",
    "in",
    "on",
    "awdl0",
    "from",
    "fe80::/10",
    "to",
    "fe80::/10",
    "port",
    "8771",
    "proto",
    "tcp",
    "comment",
    "Omdrop AirDrop receiver",
];

/// awdl0 carrying an IPv6 link-local address: the only address AirDrop
/// traffic is sent from or to. Without it there is nothing to send over and
/// nothing to bind.
pub fn awdl_link_local() -> bool {
    let (_, out) = capture(
        "ip",
        &["-6", "addr", "show", "dev", "awdl0", "scope", "link"],
    );
    String::from_utf8_lossy(&out).contains("inet6")
}

/// What the receiver needs installed. The core receiver needs nothing; the
/// Python one needs its archive library, probed by the API it calls, and
/// libkeyutils, found the way the receiver loads it (by soname, so Debian's
/// multiarch directory counts). Asked of the interpreter the receiver's unit
/// runs, not whichever python3 PATH finds first (mise, pyenv, a venv).
pub fn receiver_libs_installed() -> bool {
    if ctx().receiver.is_some() {
        return true;
    }
    let python = std::env::var("OMDROP_RECEIVER_PYTHON")
        .ok()
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| "/usr/bin/python3".to_string());
    run_quiet(
        &python,
        &[
            "-c",
            "from libarchive import stream_reader; import ctypes; ctypes.CDLL(\"libkeyutils.so.1\")",
        ],
    ) == 0
}

/// Broadcom (vendor 0x14e4) network hardware on PCI, where Apple's Wi-Fi
/// sits on Apple Silicon. A VM such as Try Omarchy has no AWDL-capable radio.
/// OMDROP_SYSFS lets the tests describe the hardware instead of depending on
/// the machine they run on.
pub fn apple_broadcom_wifi() -> bool {
    let sysfs = env_nonempty("OMDROP_SYSFS").unwrap_or_else(|| "/sys".to_string());
    let Ok(entries) = std::fs::read_dir(Path::new(&sysfs).join("bus/pci/devices")) else {
        return false;
    };
    entries.flatten().any(|e| {
        let read = |n: &str| crate::util::read_trimmed(&e.path().join(n)).unwrap_or_default();
        read("vendor") == "0x14e4" && read("class").starts_with("0x0280")
    })
}

// The radio half is a separate package: omdrop-awdl for Apple's Broadcom
// Wi-Fi, or another radio backend. A backend may describe itself through
// `<helper> probe --json`, run unprivileged (the plugin's
// docs/radio-backend.md; omdrop-radio relays its hooks' answer). One that
// does owns the hardware and installation checks for its own radio; one
// that does not is taken to be omdrop-awdl on Apple's Broadcom Wi-Fi and
// gets the Broadcom checks, unchanged. omdrop-awdl 0.9.x answers a
// subcommand it does not know with its usage and exit 2: "no probe".
// omdrop-awdl 0.10.0 and later answer through their hooks as backend
// `awdl`: their hardware and radio findings are the probe's, but the
// package is still the Broadcom driver install-driver builds and updates.

/// What the helper said when asked.
enum Probe {
    /// No answer that counts: omdrop-awdl, or no helper at all.
    None,
    /// It did not answer in time. Still a backend that probes: omdrop-awdl
    /// answers an unknown command at once, so falling back to its Broadcom
    /// checks would only tell a non-Mac it is not one.
    Hung,
    /// A JSON object with a non-empty `backend` string.
    Answer(Map<String, Value>),
}

/// `OMDROP_PROBE_TIMEOUT`, as given (the tests wait less), default 5.
fn probe_timeout() -> String {
    env_nonempty("OMDROP_PROBE_TIMEOUT").unwrap_or_else(|| "5".to_string())
}

/// The answer, if it is one: a JSON object whose `backend` is a string with
/// something in it besides whitespace.
fn parse_probe(out: &[u8]) -> Option<Map<String, Value>> {
    let Ok(Value::Object(o)) = serde_json::from_slice::<Value>(out) else {
        return None;
    };
    o.get("backend")
        .and_then(Value::as_str)
        .is_some_and(|b| !b.trim().is_empty())
        .then_some(o)
}

/// Asked once per run. The probe reads a few files and answers; one that
/// hangs would hang doctor with it, and the panel waiting on doctor, so it
/// gets OMDROP_PROBE_TIMEOUT seconds, in a process group of its own that
/// goes whole at the deadline.
fn ask_probe() -> Probe {
    let helper = &ctx().discoverable;
    if !is_executable(helper) {
        return Probe::None;
    }
    let Some(limit) = timeout_duration(&probe_timeout()) else {
        return Probe::None;
    };
    let mut cmd = Command::new(helper);
    cmd.args(["probe", "--json"]);
    match capture_bounded(&mut cmd, limit.map(|l| Instant::now() + l), PROBE_MAX) {
        Captured::TimedOut => Probe::Hung,
        // What `timeout` reports for a helper it had to stop, or that was
        // killed anyway: the same as no answer in time.
        Captured::Done(124 | 137, _) => Probe::Hung,
        Captured::Done(0, out) => parse_probe(&out).map_or(Probe::None, Probe::Answer),
        Captured::Done(..) | Captured::TooLong => Probe::None,
    }
}

static PROBE: LazyLock<Probe> = LazyLock::new(ask_probe);

fn radio_probe() -> &'static Probe {
    &PROBE
}

fn probing() -> bool {
    !matches!(radio_probe(), Probe::None)
}

/// omdrop-awdl answering through its hooks: the driver package
/// install-driver manages, whose version it checks against DRIVER_VERSION.
fn awdl_backend() -> bool {
    matches!(radio_probe(), Probe::Answer(_)) && probe_field("backend") == "awdl"
}

/// A backend that probes and is a package of its own, which install-driver
/// leaves alone. One that hangs counts: it is not known to be omdrop-awdl.
fn foreign_backend() -> bool {
    probing() && !awdl_backend()
}

fn radio_probe_hung() -> bool {
    matches!(radio_probe(), Probe::Hung)
}

fn radio_probe_hung_say() -> String {
    format!(
        "The radio backend did not answer when asked what it needs ({} probe, {} seconds). Reinstalling or updating its package may help.",
        ctx().discoverable.display(),
        probe_timeout()
    )
}

/// Python's `str()`, which the plugin's probe readers print with.
fn py_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::Null => "None".to_string(),
        other => other.to_string(),
    }
}

fn py_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// One field of the probe as text: strings as they are, booleans as
/// true/false, anything absent as nothing.
fn probe_field(name: &str) -> String {
    let Probe::Answer(o) = radio_probe() else {
        return String::new();
    };
    let text = match o.get(name) {
        None | Some(Value::Null) => return String::new(),
        Some(Value::Bool(b)) => b.to_string(),
        Some(v) => py_str(v),
    };
    strip_trailing_newlines(&text).to_string()
}

/// The backend's blockers, in its order, with an ID the panel acts on
/// renamed backend-<id> and each sentence on one line.
fn probe_missing() -> Vec<(String, String)> {
    let Probe::Answer(o) = radio_probe() else {
        return Vec::new();
    };
    let Some(Value::Array(items)) = o.get("missing") else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|m| {
            let m = m.as_object()?;
            let id = m.get("id").filter(|v| py_truthy(v))?;
            let say = m.get("say").filter(|v| py_truthy(v))?;
            let id = py_str(id);
            let id = if PLUGIN_ITEM_IDS.contains(&id.as_str()) {
                format!("backend-{id}")
            } else {
                id
            };
            let say = py_str(say).split_whitespace().collect::<Vec<_>>().join(" ");
            Some((id, say))
        })
        .collect()
}

fn or_none(s: &str) -> &str {
    if s.is_empty() { "none" } else { s }
}

/// Whether the backend follows at least the minimum contract. One that
/// names none is taken to follow none.
fn backend_contract_ok() -> bool {
    let contract = probe_field("contract");
    !contract.is_empty() && vercmp(&contract, BACKEND_CONTRACT_MIN).is_ge()
}

fn backend_contract_say() -> String {
    format!(
        "The installed radio backend ({}) follows helper contract {}, older than the {BACKEND_CONTRACT_MIN} this version of Omdrop needs. Update its package.",
        probe_field("backend"),
        or_none(&probe_field("contract"))
    )
}

/// For messages that ask for a newer or missing radio helper: what provides
/// it. `omdrop install-driver` builds omdrop-awdl, with or without its
/// hooks; any other backend that probes is a package of its own, which that
/// command leaves alone.
pub fn radio_pkg() -> &'static str {
    if foreign_backend() {
        "radio backend"
    } else {
        "Wi-Fi driver package"
    }
}

/// And how to update it.
pub fn radio_update() -> String {
    if !foreign_backend() {
        return "Update it with: omdrop install-driver".to_string();
    }
    let backend = probe_field("backend");
    let named = if backend.is_empty() {
        String::new()
    } else {
        format!(" ({backend})")
    };
    format!("Update the package that provides it{named}: omdrop install-driver leaves it alone.")
}

/// An installed package's version, from pacman.
fn installed_pkg(name: &str) -> Option<String> {
    let (code, out) = capture("pacman", &["-Q", name]);
    if code != 0 {
        return None;
    }
    let text = crate::util::strip_trailing_newlines(&String::from_utf8_lossy(&out)).to_string();
    Some(text.rsplit(' ').next().unwrap_or_default().to_string())
}

/// Whether version `a` is older than `b`, in pacman's order.
pub fn version_lt(a: &str, b: &str) -> bool {
    vercmp(a, b).is_lt()
}

/// pacman's version order (libalpm's `alpm_pkg_vercmp`), here rather than by
/// running `vercmp`: Debian and Ubuntu have no `vercmp`, and treating its
/// absence as "not older" let any backend contract through the identity
/// check there.
fn vercmp(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let (e1, v1, r1) = parse_evr(a);
    let (e2, v2, r2) = parse_evr(b);
    rpmvercmp(e1, e2)
        .then_with(|| rpmvercmp(v1, v2))
        .then_with(|| match (r1, r2) {
            (Some(r1), Some(r2)) => rpmvercmp(r1, r2),
            _ => Ordering::Equal,
        })
}

/// `[epoch:]version[-release]`. The epoch is only leading digits before a
/// colon, and the release starts at the last dash after them.
fn parse_evr(s: &str) -> (&str, &str, Option<&str>) {
    let digits = s.bytes().take_while(u8::is_ascii_digit).count();
    let (epoch, rest) = match s[digits..].strip_prefix(':') {
        Some(rest) if digits == 0 => ("0", rest),
        Some(rest) => (&s[..digits], rest),
        None => ("0", s),
    };
    match rest.rfind('-') {
        Some(dash) => (epoch, &rest[..dash], Some(&rest[dash + 1..])),
        None => (epoch, rest, None),
    }
}

/// libalpm's `rpmvercmp`: runs of digits compare as numbers, runs of letters
/// as strings, a number beats letters, and a longer separator run wins.
fn rpmvercmp(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut one, mut two) = (0, 0);
    let (mut seg1, mut seg2) = (0, 0);
    while one < a.len() && two < b.len() {
        while one < a.len() && !a[one].is_ascii_alphanumeric() {
            one += 1;
        }
        while two < b.len() && !b[two].is_ascii_alphanumeric() {
            two += 1;
        }
        if one >= a.len() || two >= b.len() {
            break;
        }
        if one - seg1 != two - seg2 {
            return (one - seg1).cmp(&(two - seg2));
        }
        let numeric = a[one].is_ascii_digit();
        let kind = |c: &u8| {
            if numeric {
                c.is_ascii_digit()
            } else {
                c.is_ascii_alphabetic()
            }
        };
        seg1 = one + a[one..].iter().take_while(|c| kind(c)).count();
        seg2 = two + b[two..].iter().take_while(|c| kind(c)).count();
        if seg2 == two {
            // A number against letters: the number is newer.
            return if numeric {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }
        let (mut x, mut y) = (&a[one..seg1], &b[two..seg2]);
        if numeric {
            while x.first() == Some(&b'0') {
                x = &x[1..];
            }
            while y.first() == Some(&b'0') {
                y = &y[1..];
            }
            match x.len().cmp(&y.len()) {
                Ordering::Equal => {}
                longer => return longer,
            }
        }
        match x.cmp(y) {
            Ordering::Equal => {}
            other => return other,
        }
        one = seg1;
        two = seg2;
    }
    let (rest1, rest2) = (&a[one..], &b[two..]);
    if rest1.is_empty() && rest2.is_empty() {
        return Ordering::Equal;
    }
    // Never let a trailing alpha segment beat nothing: 1.0a is older than 1.0.
    let alpha = |s: &[u8]| s.first().is_some_and(u8::is_ascii_alphabetic);
    if (rest1.is_empty() && !alpha(rest2)) || alpha(rest1) {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

/// Whether the installed driver is at least the one this release pins.
/// Read from pacman, because a helper fix is invisible from outside it.
pub fn driver_current() -> bool {
    installed_pkg(DRIVER_PKG).is_some_and(|v| vercmp(&v, DRIVER_VERSION).is_ge())
}

/// With omdrop-awdl's hooks installed: a driver older than the one this
/// release pins, as the `driver` item, whose button runs install-driver.
/// The hooks' own probe cannot tell, as it is the installed package's.
fn driver_outdated() -> Option<(String, String)> {
    (!driver_current()).then(|| {
        (
            "driver".to_string(),
            format!(
                "The Wi-Fi driver is older than the {DRIVER_VERSION} this version of Omdrop needs (installed: {}). Update it with: omdrop install-driver",
                or_none(&installed_pkg(DRIVER_PKG).unwrap_or_default())
            ),
        )
    })
}

const CORE_PKG: &str = "omdrop-core";

/// The omdrop-core the plugin carries, as core/PKGBUILD's pkgver-pkgrel:
/// core/ bumps one of them whenever it changes in a release, so an older
/// installed package is one built from an older plugin.
fn core_wanted(plugin: &Path) -> Option<String> {
    let text = std::fs::read_to_string(plugin.join("core/PKGBUILD")).ok()?;
    let field = |key: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(key))
            .filter(|v| !v.is_empty())
    };
    Some(format!("{}-{}", field("pkgver=")?, field("pkgrel=")?))
}

/// Where `omdrop install-core` installs: Apple's Broadcom Wi-Fi, with
/// omdrop-awdl's helper or its hooks, on hardware that backend says it can
/// drive, until core has run on other backends.
fn core_supported() -> bool {
    match radio_probe() {
        Probe::None => apple_broadcom_wifi(),
        _ => awdl_backend() && probe_field("hardware") != "false",
    }
}

/// Optional updates, never blockers: an installed omdrop-core older than
/// the one the plugin carries. The plugin's bash offers the first install.
pub fn core_offers() -> Vec<(String, String)> {
    let Some(want) = ctx().plugin_dir().and_then(core_wanted) else {
        return Vec::new();
    };
    let Some(have) = installed_pkg(CORE_PKG) else {
        return Vec::new();
    };
    if vercmp(&have, &want).is_lt() && core_supported() {
        return vec![(
            "core".to_string(),
            format!(
                "omdrop-core {have} is older than the {want} this plugin carries. Update it with: omdrop install-core"
            ),
        )];
    }
    Vec::new()
}

/// Installing core is the plugin's job, done before core exists, so there
/// is one installer: the plugin's own. The plugin's bin/omdrop runs
/// install-core itself and never hands it here; this is for someone who runs
/// core's binary directly.
pub fn cmd_install_core() -> i32 {
    use std::os::unix::process::CommandExt;
    let Some(plugin) = ctx().plugin_dir() else {
        die(
            "omdrop install-core builds omdrop-core from the Omdrop plugin, and no plugin was found.",
        );
    };
    let script = plugin.join("bin/omdrop");
    let err = Command::new(&script)
        .arg("install-core")
        .env("OMDROP_IMPLEMENTATION", "python")
        .exec();
    die(format!("could not run {}: {err}", script.display()))
}

/// Moving the Apple identity off disk needs a driver whose sender follows the
/// identity contract: an older one finds certificate.pem missing and makes a
/// self-signed pair under the Apple identity's names. A backend that probes
/// states the contract it follows (omdrop-awdl's hooks state their package
/// version); otherwise the driver package's version is the contract.
pub fn driver_identity_ready() {
    match radio_probe() {
        Probe::Hung => die(radio_probe_hung_say()),
        Probe::Answer(_) => {
            let installed = probe_field("contract");
            if installed.is_empty() || vercmp(&installed, DRIVER_IDENTITY_VERSION).is_lt() {
                die(format!(
                    "Keeping the identity in 1Password needs a radio backend that follows contract {DRIVER_IDENTITY_VERSION} or newer ({} follows {}).",
                    probe_field("backend"),
                    or_none(&installed)
                ));
            }
            return;
        }
        Probe::None => {}
    }
    let installed = installed_pkg(DRIVER_PKG).unwrap_or_default();
    let too_old = installed.is_empty() || vercmp(&installed, DRIVER_IDENTITY_VERSION).is_lt();
    if too_old {
        die(format!(
            "Keeping the identity in 1Password needs driver {DRIVER_IDENTITY_VERSION} or newer (installed: {}). Update it with: omdrop install-driver",
            or_none(&installed)
        ));
    }
}

fn service_missing() -> Option<(String, String)> {
    (!crate::status::have_unit()).then(|| {
        (
            "service".to_string(),
            "The service that receives files is not installed yet. Turning Omdrop on installs it."
                .to_string(),
        )
    })
}

/// For a backend whose probe says `hardware: false`: its own `hardware`
/// items, or the plugin's sentence when it names none.
fn backend_hardware_missing() -> Vec<(String, String)> {
    let mut missing: Vec<_> = probe_missing()
        .into_iter()
        .filter(|(id, _)| id == "hardware")
        .collect();
    if missing.is_empty() {
        missing.push((
            "hardware".to_string(),
            format!(
                "This computer's Wi-Fi is not one the installed radio backend ({}) can drive.",
                probe_field("backend")
            ),
        ));
    }
    missing
}

/// What is missing, in the order it has to be fixed, one (id, sentence)
/// each: the id is for the panel, which offers to fix the one thing it
/// can, and the sentence is for someone holding a laptop.
pub fn prereqs_missing() -> Vec<(String, String)> {
    let mut missing = Vec::new();
    match radio_probe() {
        // A backend that does not answer is alone: install-driver refuses to
        // run for it, so a library item would offer the panel's button for
        // nothing.
        Probe::Hung => {
            missing.push(("backend".to_string(), radio_probe_hung_say()));
            return missing;
        }
        Probe::Answer(_) => {
            // Hardware the backend cannot drive is, again, first and alone.
            if probe_field("hardware") == "false" {
                missing.extend(backend_hardware_missing());
                return missing;
            }
            if !backend_contract_ok() {
                missing.push(("backend".to_string(), backend_contract_say()));
            }
            // omdrop-awdl's hooks report what they see; how old the driver
            // package is, against this release's pin, is Omdrop's to say. It
            // comes as Omdrop's own `driver` item, so the panel offers its
            // button: the probe's items still have reserved IDs renamed.
            if awdl_backend() {
                missing.extend(driver_outdated());
            }
            missing.extend(probe_missing());
            if !receiver_libs_installed() {
                missing.push((
                    "library".to_string(),
                    format!("Packages the receiver needs ({RECEIVER_PKGS}) are not installed. The button below installs them."),
                ));
            }
            missing.extend(service_missing());
            missing.extend(firewall_item());
            return missing;
        }
        Probe::None => {}
    }
    // First, and alone: nothing else on this list can be fixed here.
    if !apple_broadcom_wifi() {
        missing.push(("hardware".to_string(), NO_BROADCOM.to_string()));
        return missing;
    }
    if !receiver_libs_installed() {
        missing.push((
            "library".to_string(),
            format!("Packages the receiver needs ({RECEIVER_PKGS}) are not installed. The button below installs them along with the driver."),
        ));
    }
    if !is_executable(&ctx().discoverable) {
        missing.push((
            "driver".to_string(),
            "The Wi-Fi driver that makes this computer visible to Apple devices is not installed. It has to be installed as an administrator.".to_string(),
        ));
    } else if !Path::new("/sys/class/net/awdl0").exists() {
        missing.push((
            "radio".to_string(),
            "The driver is installed but its Apple-compatible radio is not running yet, so nobody can see this computer. Restarting usually brings it up.".to_string(),
        ));
    }
    missing.extend(service_missing());
    missing.extend(firewall_item());
    missing
}

#[derive(Serialize)]
struct Missing<'a> {
    id: &'a str,
    say: &'a str,
}

fn rows(v: &[(String, String)]) -> Vec<Missing<'_>> {
    v.iter().map(|(id, say)| Missing { id, say }).collect()
}

#[derive(Serialize)]
struct Doctor<'a> {
    ready: bool,
    missing: Vec<Missing<'a>>,
    offers: Vec<Missing<'a>>,
}

/// The panel's version of `setup`'s answer: --json so the widget can render
/// the first blocking sentence and know whether it can offer the fix.
/// `offers` are optional and never make it unready.
pub fn cmd_doctor(args: &[String]) -> i32 {
    let missing = prereqs_missing();
    let offers = core_offers();
    if args.first().is_some_and(|a| a == "--json") {
        let d = Doctor {
            ready: missing.is_empty(),
            missing: rows(&missing),
            offers: rows(&offers),
        };
        outln!("{}", py_json(&d));
        return 0;
    }
    if missing.is_empty() {
        outln!("Ready to receive.");
    } else {
        outln!("Not ready to receive yet:");
        for (_, say) in &missing {
            outln!("  - {say}");
        }
    }
    if !offers.is_empty() {
        outln!("\nTo do:");
        for (_, say) in &offers {
            outln!("  - {say}");
        }
    }
    // Which identity Apple devices will see, and anything left behind.
    // Reported, never repaired here: `omdrop off` is what clears a window.
    outln!();
    if id(&["status"], Out::Inherit, false).code != 0 {
        outln!("The identity could not be read.");
    }
    if ctx().window_file().exists() && !crate::status::receiving() {
        outln!(
            "A window's identity file remains although nothing is receiving. Clear it with: omdrop off"
        );
    }
    0
}

fn ufw_active() -> bool {
    have("ufw") && run_quiet("systemctl", &["is-active", "--quiet", "ufw.service"]) == 0
}

/// UFW keeps each rule in its rules file as a `### tuple ###` line, which
/// unlike `ufw status` takes no root to read. Ours, as `ufw` writes it,
/// followed by its comment.
const UFW_TUPLE: &str = "### tuple ### allow tcp 8771 fe80::/10 any fe80::/10 in_awdl0";

/// /etc, or OMDROP_UFW_ETC in the tests.
fn ufw_etc() -> String {
    env_nonempty("OMDROP_UFW_ETC").unwrap_or_else(|| "/etc".to_string())
}

fn ufw_rules() -> Option<String> {
    std::fs::read_to_string(format!("{}/ufw/user6.rules", ufw_etc())).ok()
}

/// Whether our rule is in UFW's rules; `None` when the file can't be read.
fn ufw_rule_present() -> Option<bool> {
    Some(ufw_rules()?.lines().any(|line| {
        line.strip_prefix(UFW_TUPLE)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(' '))
    }))
}

/// Whether a tuple's destination ports (`any`, or a list of ports and
/// `lo:hi` ranges) include the receiver's.
fn ports_cover_receiver(ports: &str) -> bool {
    ports.split(',').any(|p| {
        let (lo, hi) = p.split_once(':').unwrap_or((p, p));
        p == "any"
            || matches!((lo.parse::<u32>(), hi.parse::<u32>()), (Ok(lo), Ok(hi)) if lo <= 8771 && 8771 <= hi)
    })
}

/// Whether UFW lets senders reach the receiver; `None` when its files can't
/// be read. Yes when incoming traffic isn't dropped by default, or when any
/// allow (or limit) rule could admit TCP 8771 on awdl0: ours, or a broader
/// one such as `ufw allow 8771/tcp` or `ufw allow in on awdl0`. Rule
/// addresses aren't compared, so a rule that might match counts as one that
/// does: a false "blocked" would send someone to fix a working receiver.
fn ufw_admits_receiver() -> Option<bool> {
    let policy = std::fs::read_to_string(format!("{}/default/ufw", ufw_etc())).ok()?;
    let rules = ufw_rules()?;
    let input = policy.lines().find_map(|l| {
        l.trim_end()
            .strip_prefix("DEFAULT_INPUT_POLICY=")
            .map(|v| v.trim_matches('"'))
    })?;
    if input != "DROP" && input != "REJECT" {
        return Some(true);
    }
    Some(rules.lines().any(|line| {
        let Some(tuple) = line.strip_prefix("### tuple ### ") else {
            return false;
        };
        // action proto dport dst sport src [dapp sapp] direction[_iface]
        let f: Vec<&str> = tuple
            .split(" comment=")
            .next()
            .unwrap_or_default()
            .split_whitespace()
            .collect();
        (f.len() == 7 || f.len() == 9)
            && matches!(f[0].split('_').next(), Some("allow" | "limit"))
            && matches!(f[1], "tcp" | "any")
            && ports_cover_receiver(f[2])
            && matches!(f[f.len() - 1], "in" | "in_awdl0")
    }))
}

/// A blocker only when it certainly is one: UFW on and enforcing, and
/// nothing in its rules admitting the receiver. ufw.service stays active
/// after `ufw disable`, which only sets ENABLED=no, so that is checked too.
fn firewall_missing() -> bool {
    ufw_active()
        && std::fs::read_to_string(format!("{}/ufw/ufw.conf", ufw_etc()))
            .is_ok_and(|conf| conf.lines().any(|l| l == "ENABLED=yes"))
        && ufw_admits_receiver() == Some(false)
}

/// Whether install-driver adds the rule: whenever UFW is active and the rule
/// isn't known to be there. `ufw allow` skips a rule it already has.
fn firewall_needed() -> bool {
    ufw_active() && ufw_rule_present() != Some(true)
}

fn firewall_item() -> Option<(String, String)> {
    firewall_missing().then(|| {
        (
            "firewall".to_string(),
            "UFW is blocking AirDrop: Apple devices can find this computer but not connect to its receiver. The button below adds the one rule it needs.".to_string(),
        )
    })
}

/// The DKMS package deliberately does not own this rule: it supplies a radio
/// other AWDL applications can use, and opening an application port belongs
/// to the application.
pub fn cmd_firewall(args: &[String]) -> i32 {
    match args.first().map(String::as_str).unwrap_or("") {
        "install" => {
            if !have("ufw") {
                outln!("UFW is not installed; no UFW rule is needed.");
                return 0;
            }
            if run_quiet("systemctl", &["is-active", "--quiet", "ufw.service"]) != 0 {
                outln!("UFW is not active; Omdrop did not change its configuration.");
                return 0;
            }
            outln!(
                "Allowing AirDrop receiver traffic only on awdl0, from IPv6 link-local peers, to TCP 8771."
            );
            let mut a = vec!["ufw"];
            a.extend(UFW_RULE);
            run("sudo", &a)
        }
        "remove" => {
            if !have("ufw") {
                outln!("UFW is not installed; there is no Omdrop UFW rule to remove.");
                return 0;
            }
            let mut a = vec!["ufw", "--force", "delete"];
            a.extend(UFW_RULE);
            run("sudo", &a)
        }
        _ => die("usage: omdrop firewall install|remove"),
    }
}

/// The script install-driver shows or runs: the receiver's packages from the
/// official repositories by exact name, the driver from a repository when
/// one carries it, else built from the pinned commit, and the firewall rule
/// in the same terminal so sudo reuses the authentication.
pub fn build_script(
    self_q: &str,
    libs_missing: bool,
    driver_needed: bool,
    repo_has_driver: bool,
    ufw: bool,
) -> String {
    let src = format!(
        "{}/omdrop/omdrop-awdl",
        crate::util::env_nonempty("XDG_CACHE_HOME").unwrap_or_else(|| format!("{}/.cache", home()))
    );
    let mut build = String::from("set -e");
    if libs_missing {
        // --needed leaves an installed copy alone; --asdeps because it is
        // there for Omdrop, not something the user asked for by name.
        build.push_str(&format!(
            "\nsudo pacman -S --needed --asdeps {RECEIVER_PKGS}"
        ));
    }
    if driver_needed {
        if repo_has_driver {
            build.push_str(&format!(
                "\nsudo pacman -S --needed --noconfirm {DRIVER_PKG}"
            ));
        } else {
            // Into the cache directory, not a temp dir: the person keeps the
            // source they built as root, /tmp is RAM on this hardware, and a
            // later version is a pull rather than a fresh clone.
            build.push_str(&format!(
                "\nmkdir -p \"$(dirname '{src}')\"\nif [ -d '{src}/.git' ]; then\n  git -C '{src}' fetch --quiet origin\nelse\n  git clone --quiet {DRIVER_REPO} '{src}'\nfi\necho 'Building driver commit {DRIVER_COMMIT}'\ngit -C '{src}' checkout --detach e7891ab56957dde46f134c1991e4e4717f94d2e4 && makepkg --dir '{src}' -si"
            ));
        }
    }
    if ufw {
        build.push_str(&format!("\n{self_q} firewall install"));
    }
    build
}

/// Installing a kernel module is not something a bar widget may do quietly:
/// Omarchy's own pattern is a floating terminal running the command, the
/// user's own sudo prompt, all output visible -- not pkexec'ing a build
/// script out of a plugin clone, which would be root running user-writable code.
pub fn cmd_install_driver() -> i32 {
    let c = ctx();
    let self_q = shell_quote(&c.command_path().to_string_lossy());
    if foreign_backend() {
        return install_for_backend(&self_q);
    }
    // omdrop-awdl's hooks answer for the hardware; nothing is built for a
    // machine they say their driver cannot drive.
    let awdl = awdl_backend();
    if awdl && probe_field("hardware") == "false" {
        die(backend_hardware_missing().swap_remove(0).1);
    }
    let helper = is_executable(&c.discoverable);
    if helper && driver_current() && receiver_libs_installed() {
        // The firewall rule is still Omdrop's to add, as install_for_backend
        // adds it.
        if firewall_needed() {
            return install_firewall(&build_script(&self_q, false, false, false, true));
        }
        outln!(
            "The driver and the Python library the receiver needs are both installed and current. Nothing to do."
        );
        return 0;
    }
    if !awdl && !apple_broadcom_wifi() {
        die(NO_BROADCOM);
    }
    let libs_missing = !receiver_libs_installed();
    let driver_needed = !helper || !driver_current();
    // `pacman -Si` reads the sync databases already on disk and deliberately
    // does not refresh them: -Sy alone is how partial upgrades happen.
    let repo_has_driver = driver_needed && run_quiet("pacman", &["-Si", DRIVER_PKG]) == 0;
    let build = build_script(
        &self_q,
        libs_missing,
        driver_needed,
        repo_has_driver,
        firewall_needed(),
    );
    const INTRO: &str = "Omdrop requires a patched wifi driver, which requires administrative privilege to install. You will be prompted for your password.";
    if !have(LAUNCHER) {
        outln!("{INTRO}");
        outln!();
        outln!("Install the driver with:");
        outln!("\n{build}\n");
        return 0;
    }
    outln!("Opening a terminal to install the driver.");
    launch_install(&build, INTRO)
}

/// The driver and the receiver's packages are current: only the firewall
/// rule remains, run the same way as the driver install.
fn install_firewall(build: &str) -> i32 {
    if !have(LAUNCHER) {
        outln!("Add the firewall rule the receiver needs with:");
        outln!("\n{build}\n");
        return 0;
    }
    outln!("Opening a terminal to add the firewall rule the receiver needs.");
    launch_install(
        build,
        "Omdrop needs a firewall rule for its receiver, which requires administrative privilege to add. You will be prompted for your password.",
    )
}

/// With a radio backend that probes and is not omdrop-awdl, the radio is
/// that package's business: it is installed (it answered), and it reports
/// its own blockers through doctor. What remains is Omdrop's own part, the
/// receiver's packages and its firewall rule, run the same way as the
/// driver install.
fn install_for_backend(self_q: &str) -> i32 {
    // Without an answer there is no telling whether this backend is one
    // Omdrop can work with, so nothing is installed for it.
    if radio_probe_hung() {
        die(radio_probe_hung_say());
    }
    // Omdrop's part is still worth installing; the backend's update is not
    // something this command can do.
    if !backend_contract_ok() {
        errln!("{}", backend_contract_say());
    }
    let build = build_script(
        self_q,
        !receiver_libs_installed(),
        false,
        false,
        firewall_needed(),
    );
    if build == "set -e" {
        outln!(
            "The receiver's packages are installed and the radio comes from {} {}. Nothing to do.",
            probe_field("backend"),
            probe_field("version")
        );
        return 0;
    }
    if !have(LAUNCHER) {
        outln!("Install what the receiver needs with:");
        outln!("\n{build}\n");
        return 0;
    }
    outln!("Opening a terminal to install what the receiver needs.");
    launch_install(
        &build,
        "Omdrop needs a few packages for its receiver, which requires administrative privilege to install. You will be prompted for your password.",
    )
}

/// Run an install script in a floating terminal the person watches. A
/// subshell, so a failed step ends the script and not the terminal, and
/// tested on its own line, not with `||`: bash ignores `set -e` inside a
/// subshell whose status a `||` is testing. Exit 130 skips the launcher's
/// "Done!", which a failure should not show.
fn launch_install(build: &str, intro: &str) -> i32 {
    let script = format!(
        "( {build}\n); rc=$?; if [ $rc -ne 0 ]; then echo; echo \"Installing failed (exit $rc). The messages above say why.\"; read -rsn 1 -p 'Press any key to close...' </dev/tty; echo; exit 130; fi"
    );
    run(LAUNCHER, &[format!("echo '{intro}'; echo; {script}")])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_probe_needs_a_backend_name() {
        assert!(parse_probe(br#"{"backend":"owl"}"#).is_some());
        assert!(parse_probe(b"  {\"backend\":\" owl \"}\n").is_some());
        for no in [
            &br#"{}"#[..],
            br#"{"backend":"  "}"#,
            br#"{"backend":1}"#,
            br#"["owl"]"#,
            b"usage: omdrop-discoverable start|stop|status",
            br#"{"backend":"owl"} trailing"#,
        ] {
            assert!(parse_probe(no).is_none(), "{}", String::from_utf8_lossy(no));
        }
    }

    #[test]
    fn probe_values_print_as_the_plugins_python_prints_them() {
        assert_eq!(py_str(&Value::from("0.7.0")), "0.7.0");
        assert_eq!(py_str(&Value::from(true)), "True");
        assert_eq!(py_str(&Value::from(3)), "3");
        assert!(!py_truthy(&Value::from("")) && !py_truthy(&Value::from(0)));
        assert!(!py_truthy(&Value::Null) && !py_truthy(&serde_json::json!([])));
        assert!(py_truthy(&Value::from("radio")) && py_truthy(&Value::from(7)));
    }

    #[test]
    fn the_pinned_commit_is_a_full_sha_used_literally() {
        assert_eq!(DRIVER_COMMIT.len(), 40);
        assert!(
            DRIVER_COMMIT
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        let script = build_script("omdrop", true, true, false, true);
        assert!(
            script.contains(&format!("checkout --detach {DRIVER_COMMIT} && makepkg")),
            "{script}"
        );
        for line in script.lines().filter(|l| l.contains("makepkg")) {
            assert!(
                line.contains(&format!("checkout --detach {DRIVER_COMMIT} && makepkg")),
                "{line}"
            );
        }
    }

    #[test]
    fn packages_come_from_the_official_repositories_and_the_rule_comes_last() {
        let script = build_script(
            "/home/u/.config/omarchy/plugins/netmojo.omdrop/bin/omdrop",
            true,
            true,
            true,
            true,
        );
        assert!(
            script
                .lines()
                .any(|l| l == "sudo pacman -S --needed --asdeps python-libarchive-c keyutils")
        );
        assert!(
            !script.contains("yay")
                && !script.contains("paru")
                && !script.contains("aur.archlinux.org")
        );
        assert!(script.find("sudo pacman").unwrap() < script.find("firewall install").unwrap());
        assert!(!script.contains("makepkg"));
    }

    /// Pairs and the order pacman's own `vercmp` gives them: releases, epochs,
    /// letters against numbers and against nothing, separators, leading zeros,
    /// and the versions Omdrop actually compares.
    const VERSION_ORDER: &[(&str, &str, Ordering)] = &[
        ("1.5.0", "1.5.0", Ordering::Equal),
        ("1.5.1", "1.5.0", Ordering::Greater),
        ("1.5.1", "1.5", Ordering::Greater),
        ("1.0", "1.0.0", Ordering::Less),
        ("1.01", "1.1", Ordering::Equal),
        ("0.10.0", "0.9.9", Ordering::Greater),
        ("1.5.0-1", "1.5.0-2", Ordering::Less),
        ("1.5.0-2", "1.5.1-1", Ordering::Less),
        ("1.5", "1.5-1", Ordering::Equal),
        ("1.5-1", "1.5", Ordering::Equal),
        ("1.5b", "1.5", Ordering::Less),
        ("1.5b-1", "1.5", Ordering::Less),
        ("1.5b", "1.5.1", Ordering::Less),
        ("1.0a", "1.0alpha", Ordering::Less),
        ("1.0beta", "1.0rc", Ordering::Less),
        ("1.0rc", "1.0", Ordering::Less),
        ("1.5.a", "1.5", Ordering::Greater),
        ("1.5.1", "1.5.b", Ordering::Greater),
        ("2.0", "2_0", Ordering::Equal),
        ("2.0a", "2.0.a", Ordering::Less),
        ("2___a", "2_a", Ordering::Greater),
        ("0:1.0", "1.0", Ordering::Equal),
        ("1:1.0", "2.0", Ordering::Greater),
        ("1:1.0-1", "2:1.1-1", Ordering::Less),
        ("abc", "0.7.0", Ordering::Less),
        ("0.8.1", "0.7.0", Ordering::Greater),
        ("0.6.9", "0.7.0", Ordering::Less),
        ("0.9.3-1", "0.9.3", Ordering::Equal),
        ("0.1.1-1", "0.1.0-1", Ordering::Greater),
        ("6.12.0-1.1", "6.12.0-1", Ordering::Greater),
    ];

    #[test]
    fn versions_order_as_pacman_orders_them() {
        for &(a, b, want) in VERSION_ORDER {
            assert_eq!(vercmp(a, b), want, "{a} vs {b}");
            assert_eq!(vercmp(b, a), want.reverse(), "{b} vs {a}");
        }
    }
}
