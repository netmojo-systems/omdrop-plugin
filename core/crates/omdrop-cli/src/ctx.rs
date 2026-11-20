//! Where everything is: our own files, the plugin, and the programs we run.
//!
//! The bash was a file inside the plugin and found the plugin, its manifest
//! and its skill relative to itself. This command is installed as
//! `/usr/lib/omdrop-core/omdrop`, outside any plugin and off PATH: the
//! plugin's own `bin/omdrop` is the one entry point and hands commands here.
//! So the plugin is found the bash's way first (through the path we were
//! invoked by, one symlink at a time), and otherwise where Omarchy installs
//! plugins.

use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::sync::{LazyLock, OnceLock};

use crate::util::{env_nonempty, home, is_executable, which};

pub const UNIT: &str = "airdrop-receiver.service";
/// The transient .timer that closes the window.
pub const WINDOW: &str = "omdrop-window";
/// The watcher announces every file that lands and, in one-file mode, turns
/// us off after the first. Its own ExecStart carries the window's shape.
pub const WATCH: &str = "omdrop-watch";
/// Turns a window off at the 1Password cache's hard expiry: a kernel timeout
/// clears the cache, but only stopping the receiver clears the copy it loaded.
pub const ID_EXPIRY: &str = "omdrop-identity-expiry";
/// Being visible to Everyone is not a state to leave on by accident, so `on`
/// is bounded unless you say otherwise. Ten minutes is what iOS uses.
pub const DEFAULT_WINDOW: &str = "10m";
/// An iPhone opens its AirDrop listener in short bursts, so the sender polls
/// for one; this is how long `send` gives it. A Mac in Everyone mode listens
/// throughout and never spends a second of it.
pub const DEFAULT_SEND_WAIT: &str = "30";
pub const PLUGIN_ID: &str = "netmojo.omdrop";

/// Where the package installs every core program, this command included.
pub const CORE_LIBEXEC: &str = "/usr/lib/omdrop-core";
/// The 0.9.x driver's helpers.
pub const LEGACY_LIBEXEC: &str = "/usr/lib/omdrop";
/// Present only when an omdrop-awdl with the backend contract is installed;
/// `omdrop-radio` does nothing useful without its hooks.
pub const RADIO_HOOKS: &str = "/usr/lib/omdrop/radio";

pub struct Ctx {
    /// Our own executable, symlinks resolved: what `systemd-run` and the
    /// notification re-run (the bash's `$SELF`).
    pub self_exe: PathBuf,
    /// The bash's `$PROJ`: the directory above our own.
    pub proj: PathBuf,
    pub config_home: PathBuf,
    /// ~/.config/airdrop/config.toml, read by the receiver.
    pub config: PathBuf,
    /// omdrop's own settings, apart from config.toml on purpose: the receiver
    /// refuses to start on a key it does not recognise.
    pub settings: PathBuf,
    /// Contacts Only: `visibility` and `known-senders`, read by the receiver.
    pub contacts_dir: PathBuf,
    pub runtime: PathBuf,
    pub discoverable: PathBuf,
    pub sender: PathBuf,
    /// The sender is core's own `send-to-peer`, which cleans every peer name onto one row.
    pub core_sender: bool,
    /// `None`: the plugin's `airdrop-serve.py`.
    pub receiver: Option<PathBuf>,
    pub legacy: bool,
    pub name_wait: u64,
    argv0: OsString,
    plugin: OnceLock<Option<Plugin>>,
    command: OnceLock<PathBuf>,
}

#[derive(Clone)]
pub struct Plugin {
    pub dir: PathBuf,
}

static CTX: LazyLock<Ctx> = LazyLock::new(Ctx::from_env);

pub fn ctx() -> &'static Ctx {
    &CTX
}

impl Ctx {
    fn from_env() -> Self {
        let home = home();
        let config_home = env_nonempty("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(format!("{home}/.config")));
        let runtime = env_nonempty("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                // SAFETY: getuid cannot fail.
                PathBuf::from(format!("/run/user/{}", unsafe { libc::getuid() }))
            });
        let self_exe = self_exe();
        let proj = self_exe
            .parent()
            .and_then(Path::parent)
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("/"));
        let legacy = implementation().is_ok_and(|python| python);
        let argv0 = std::env::args_os().next().unwrap_or_default();
        let siblings = sibling_dirs(&self_exe);

        let discoverable = find_discoverable(legacy, &proj);
        let sender = find_sender(legacy, &siblings, &proj);
        let core_sender = !legacy
            && find_sibling(&siblings, "send-to-peer")
                .map(resolved)
                .as_ref()
                == Some(&sender);
        let receiver = if legacy {
            None
        } else {
            find_sibling(&siblings, "omdrop-receiver")
        };

        Self {
            self_exe,
            proj,
            config: config_home.join("airdrop/config.toml"),
            settings: config_home.join("omdrop/settings"),
            contacts_dir: config_home.join("omdrop"),
            config_home,
            runtime,
            discoverable,
            sender,
            core_sender,
            receiver,
            legacy,
            name_wait: name_wait(std::env::var("OMDROP_NAME_WAIT").ok().as_deref()),
            argv0,
            plugin: OnceLock::new(),
            command: OnceLock::new(),
        }
    }

    pub fn state_dir(&self) -> PathBuf {
        self.runtime.join("omdrop")
    }

    pub fn window_file(&self) -> PathBuf {
        self.state_dir().join("window")
    }

    /// The plugin, for the unit template, the skill and the version.
    pub fn plugin(&self) -> Option<&Plugin> {
        self.plugin
            .get_or_init(|| find_plugin(&self.argv0))
            .as_ref()
    }

    pub fn plugin_dir(&self) -> Option<&Path> {
        self.plugin().map(|p| p.dir.as_path())
    }

    /// How to run omdrop again -- for the systemd units, the notification,
    /// `send`'s automatic `on`, desktop entries and the PATH link: the
    /// plugin's own `bin/omdrop`, the one entry point, so the new process
    /// gets the plugin's CORE_MIN and OMDROP_IMPLEMENTATION checks and finds
    /// the same plugin even outside the default directory; without a plugin,
    /// ourselves.
    pub fn command_path(&self) -> &Path {
        self.command.get_or_init(|| match self.plugin() {
            Some(p) => p.dir.join("bin/omdrop"),
            None => self.self_exe.clone(),
        })
    }
}

/// `OMDROP_IMPLEMENTATION`: `Ok(true)` for `python` (the bash and Python
/// programs), `Ok(false)` for `rust` or unset (ours, falling back to a
/// backend's own helper when it ships no hooks). Anything else is refused at
/// startup, so a typo cannot quietly pick a stack.
pub fn implementation() -> Result<bool, String> {
    match std::env::var("OMDROP_IMPLEMENTATION").as_deref() {
        Ok("python") => Ok(true),
        Ok("rust") | Ok("") | Err(_) => Ok(false),
        Ok(other) => Err(format!(
            "OMDROP_IMPLEMENTATION must be python or rust, not {other:?}"
        )),
    }
}

/// `readlink -f /proc/self/exe`, minus the " (deleted)" a package upgrade
/// leaves on a running binary, so the next `systemd-run $SELF` finds the new one.
fn self_exe() -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("omdrop"));
    let bytes = exe.as_os_str().as_bytes();
    match bytes.strip_suffix(b" (deleted)") {
        Some(b) => PathBuf::from(std::ffi::OsStr::from_bytes(b)),
        None => exe,
    }
}

/// Where a core helper sits relative to this executable: beside it. The
/// package installs every program in /usr/lib/omdrop-core, and
/// `cargo build --workspace` puts every binary of a development build in one
/// directory.
pub fn sibling_dirs(exe: &Path) -> Vec<PathBuf> {
    exe.parent().map(Path::to_path_buf).into_iter().collect()
}

fn find_sibling(dirs: &[PathBuf], name: &str) -> Option<PathBuf> {
    dirs.iter()
        .map(|d| d.join(name))
        .find(|p| p.is_file() && is_executable(p))
}

/// Resolve symlinks, as the bash did: helpers find their own siblings
/// through their path, and the polkit rule matches the real one.
fn resolved(p: PathBuf) -> PathBuf {
    if p.exists() {
        std::fs::canonicalize(&p).unwrap_or(p)
    } else {
        p
    }
}

/// The sending half: an override, the core `send-to-peer` beside us, the
/// driver's packaged one, anything on PATH, then a source checkout's tools/.
fn find_sender(legacy: bool, siblings: &[PathBuf], proj: &Path) -> PathBuf {
    let found = env_nonempty("OMDROP_SENDER")
        .map(PathBuf::from)
        .or_else(|| {
            if legacy {
                None
            } else {
                find_sibling(siblings, "send-to-peer")
            }
        })
        .or_else(|| {
            let p = Path::new(LEGACY_LIBEXEC).join("send-to-peer");
            is_executable(&p).then_some(p)
        })
        .or_else(|| which("send-to-peer"))
        .unwrap_or_else(|| proj.join("tools/send-to-peer"));
    resolved(found)
}

/// The radio half, which makes us discoverable. `omdrop-radio` is the core
/// helper bound to the polkit action org.omarchy.omdrop.radio; it needs the
/// driver's backend hooks, so without them the 0.9.x helper still serves.
fn find_discoverable(legacy: bool, proj: &Path) -> PathBuf {
    let core = Path::new(CORE_LIBEXEC).join("omdrop-radio");
    let found = env_nonempty("OMDROP_DISCOVERABLE")
        .map(PathBuf::from)
        .or_else(|| {
            (!legacy && is_executable(&core) && Path::new(RADIO_HOOKS).is_dir()).then_some(core)
        })
        .or_else(|| {
            let p = Path::new(LEGACY_LIBEXEC).join("omdrop-discoverable");
            is_executable(&p).then_some(p)
        })
        .or_else(|| which("awdl-discoverable"))
        .unwrap_or_else(|| proj.join("tools/awdl-discoverable"));
    resolved(found)
}

/// Decimal seconds for named discovery: leading zeros stripped, bounded
/// before conversion so oversized values cannot wrap; anything else is 120.
pub fn name_wait(raw: Option<&str>) -> u64 {
    let raw = raw.unwrap_or("120");
    let digits = raw.trim_start_matches('0');
    if !digits.is_empty()
        && digits.len() <= 10
        && digits.bytes().all(|b| b.is_ascii_digit())
        && let Ok(n) = digits.parse::<u64>()
        && n <= 2_147_483_647
    {
        return n;
    }
    120
}

/// The plugin directory. Through the path we were run as first, following
/// it one symlink at a time and stopping at the first directory whose parent
/// holds manifest.json -- not straight to the real path: during development
/// a plugin's bin/omdrop can itself be a symlink into a source checkout, and
/// resolving all the way lands beside the program instead of beside the
/// files that shipped with it. Then where `omarchy plugin add` puts it.
fn find_plugin(argv0: &OsString) -> Option<Plugin> {
    if let Some(dir) = plugin_from_invocation(argv0) {
        return Some(Plugin { dir });
    }
    let mut candidates = Vec::new();
    if let Some(x) = env_nonempty("XDG_CONFIG_HOME") {
        candidates.push(PathBuf::from(x).join("omarchy/plugins").join(PLUGIN_ID));
    }
    candidates.push(
        PathBuf::from(home())
            .join(".config/omarchy/plugins")
            .join(PLUGIN_ID),
    );
    candidates
        .into_iter()
        .find(|d| d.join("manifest.json").is_file())
        .map(|dir| Plugin { dir })
}

fn plugin_from_invocation(argv0: &OsString) -> Option<PathBuf> {
    let a = Path::new(argv0);
    let mut path = if a.as_os_str().as_bytes().contains(&b'/') {
        a.to_path_buf()
    } else {
        which(&argv0.to_string_lossy())?
    };
    for _ in 0..16 {
        let dir = logical(&path.parent().unwrap_or(Path::new(".")).join(".."))?;
        if crate::util::is_readable(&dir.join("manifest.json")) {
            return Some(dir);
        }
        let meta = std::fs::symlink_metadata(&path).ok()?;
        if !meta.file_type().is_symlink() {
            return None;
        }
        let next = std::fs::read_link(&path).ok()?;
        path = if next.is_absolute() {
            next
        } else {
            path.parent().unwrap_or(Path::new(".")).join(next)
        };
    }
    None
}

/// `cd DIR && pwd`: absolute, `..` removed lexically, symlinks kept. `None`
/// when the directory does not exist.
pub fn logical(p: &Path) -> Option<PathBuf> {
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        let cwd = std::env::var_os("PWD")
            .map(PathBuf::from)
            .filter(|w| w.is_absolute() && same_file(w, Path::new(".")))
            .or_else(|| std::env::current_dir().ok())?;
        cwd.join(p)
    };
    let mut out = PathBuf::from("/");
    for c in abs.components() {
        match c {
            Component::RootDir | Component::Prefix(_) | Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(n) => out.push(n),
        }
    }
    out.is_dir().then_some(out)
}

fn same_file(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(x), Ok(y)) => x.dev() == y.dev() && x.ino() == y.ino(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_wait_is_decimal_and_bounded() {
        for (raw, want) in [
            ("0008", 8),
            ("0000000000000000009", 9),
            ("2147483647", 2_147_483_647),
            ("0", 120),
            ("000", 120),
            ("-1", 120),
            ("1+1", 120),
            ("08x", 120),
            ("2147483648", 120),
            ("99999999999999999999", 120),
            ("", 120),
        ] {
            assert_eq!(name_wait(Some(raw)), want, "{raw}");
        }
        assert_eq!(name_wait(None), 120);
    }

    #[test]
    fn siblings_are_beside_the_command_in_the_package_and_a_build() {
        assert_eq!(
            sibling_dirs(Path::new("/usr/lib/omdrop-core/omdrop")),
            vec![PathBuf::from("/usr/lib/omdrop-core")]
        );
        assert_eq!(
            sibling_dirs(Path::new("/tmp/t/debug/omdrop")),
            vec![PathBuf::from("/tmp/t/debug")]
        );
    }

    #[test]
    fn helpers_are_found_beside_a_command_in_a_lib_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let lib = tmp.path().join("usr/lib/omdrop-core");
        std::fs::create_dir_all(&lib).unwrap();
        for prog in ["omdrop", "send-to-peer", "omdrop-receiver"] {
            let p = lib.join(prog);
            std::fs::write(&p, "#!/bin/sh\n").unwrap();
            let exec = std::os::unix::fs::PermissionsExt::from_mode(0o755);
            std::fs::set_permissions(&p, exec).unwrap();
        }
        let siblings = sibling_dirs(&lib.join("omdrop"));
        assert_eq!(
            find_sibling(&siblings, "send-to-peer"),
            Some(lib.join("send-to-peer"))
        );
        assert_eq!(
            find_sibling(&siblings, "omdrop-receiver"),
            Some(lib.join("omdrop-receiver"))
        );
        assert_eq!(find_sibling(&siblings, "omdrop-adv"), None);
    }

    #[test]
    fn the_plugin_is_found_through_a_link_to_its_command() {
        let tmp = tempfile::tempdir().unwrap();
        let plugin = tmp.path().join("plugins/netmojo.omdrop");
        std::fs::create_dir_all(plugin.join("bin")).unwrap();
        std::fs::write(plugin.join("manifest.json"), "{}").unwrap();
        std::fs::write(plugin.join("bin/omdrop"), "").unwrap();
        let bin = tmp.path().join("local/bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::os::unix::fs::symlink(plugin.join("bin/omdrop"), bin.join("omdrop")).unwrap();
        let found = plugin_from_invocation(&bin.join("omdrop").into_os_string());
        assert_eq!(found, Some(plugin));
        assert_eq!(
            plugin_from_invocation(&tmp.path().join("nowhere/omdrop").into_os_string()),
            None
        );
    }
}
