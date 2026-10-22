# omdrop-core

The radio-independent half of Omdrop, AirDrop for Omarchy, in Rust: the `omdrop` command, the AirDrop receiver and sender, identity, the advertisers, and the one root entry point. It lives in `core/` of the [omdrop-plugin](https://github.com/netmojo-systems/omdrop-plugin) repository, beside the panel that uses it. A radio backend supplies the hooks that bring up `awdl0`; see [the backend contract](docs/backend-contract.md).

**Status:** the default wherever the radio backend supports it: today omdrop-awdl. omdrop-owl ships these hooks since 0.4.0, so the plugin hands commands to a core already installed there, but doesn't offer core on it until it has been tested on owl hardware (#73). On other backends the plugin runs its bash and Python programs. `omdrop install-core`, which `omdrop setup` and `omdrop doctor` offer with a supported backend, installs the `omdrop-core` package: from the package repositories when they carry the plugin's version, and otherwise built from this directory with makepkg. It never runs from the plugin's clone, because the root helper must sit at a fixed root-owned path.

The package installs every program in `/usr/lib/omdrop-core/`, `omdrop` included, and nothing on `PATH`. The plugin's `omdrop` is the one command people and the panel run: when `/usr/lib/omdrop-core/omdrop` is installed and reports at least the plugin's `CORE_MIN`, the plugin's `bin/omdrop` hands every command to it. Below `CORE_MIN`, or when its version can't be read, the bash and Python programs run, and `omdrop doctor` says how to update core. `OMDROP_IMPLEMENTATION=python` keeps the bash and Python programs; `rust` requires a core at least `CORE_MIN`. Core's `omdrop` moves to `/usr/bin/omdrop` only once omdrop-owl runs on core and cores older than this hand-off are gone. The plugin reads core's version from the `omdrop-core <version>` line `omdrop version` prints, which is the workspace version in `Cargo.toml`, so keep that line's format. Each program is a drop-in for the one it replaces, with the same arguments, output, files and exit codes, so the old programs remain a fallback.

Proven live against a Mac and an iPhone (October 2026):
- the receiver, in Everyone and Contacts Only, including HEIC originals and 141.6 MB videos (six of six byte-identical);
- the sender, to a Mac in Contacts Only, and to an iPhone in Everyone (a file and a link) and in Contacts Only.

`omdrop-radio` with the Broadcom hooks ran live on 2026-10-15: windows through the plugin, stop, stop→start, natural expiry, and iPhone and Mac transfers in Contacts Only. A side-by-side comparison with the Python stack on one machine found no case where Python succeeded and Rust failed. Not yet proven: the omdrop-owl backend, BLE wake, a packaged (non-mixed) install, Decline and the Ask thumbnail on an iPhone, and longer fuzzing.

## Programs

|Installed as|Crate|Replaces|Runs as|
|---|---|---|---|
|`/usr/lib/omdrop-core/omdrop`|`omdrop-cli`|omdrop-plugin `bin/omdrop`, `bin/pick.py`, which runs it|user|
|`/usr/lib/omdrop-core/omdrop-receiver`|`omdrop-receiver`|omdrop-plugin `bin/airdrop-serve.py`|user (systemd user unit)|
|`/usr/lib/omdrop-core/send-to-peer`|`omdrop-send`|omdrop-awdl `userspace/send-to-peer`|user|
|`/usr/lib/omdrop-core/airdrop-send`|`omdrop-send`|omdrop-awdl `userspace/airdrop-send.py`|user|
|`/usr/lib/omdrop-core/omdrop-radio`|`omdrop-radio`|the core of omdrop-awdl `userspace/omdrop-discoverable`|root, through polkit action `org.omarchy.omdrop.radio`|
|`/usr/lib/omdrop-core/omdrop-adv`|`omdrop-adv`|omdrop-awdl `ble-airdrop-adv.py`, `awdl-mdns-respond.py`, `awdl-airdrop-adv.py`|root (and user for the `ble` wake)|

Libraries:

- `omdrop-identity`: the [identity contract](https://github.com/netmojo-systems/omdrop-awdl/blob/main/docs/identity-contract.md), the kernel-keyring cache, the disk and self-signed identities, and the 1Password lifecycle. Passes the shared `identity-vectors.json`.
- `omdrop-proto`: TLS, DVZip and cpio, HTTP framing, bounded plist parsing, the Contacts Only policy, and debug dumps.

What changes for users, compared with the Python and bash programs:

- No Python runtime, and none of `python-libarchive-c`, `python-pillow`, `python-zeroconf`, `python-ifaddr`, `python-dbus` or `python-gobject`.
- Untrusted network input is parsed in Rust: archives no longer go through libarchive, and plists are parsed with size, count and depth limits.
- The root helper is no longer bash. Its radio-specific work runs as backend hooks with a fixed, cleared environment.

## Build

Needs Rust 1.88 or newer, the `rust-version` in `Cargo.toml`.

```bash
cargo build --release --workspace
```

To build and install the package:

```bash
makepkg -si
```

`omdrop-radio` needs a backend that installs hooks in `/usr/lib/omdrop/radio/`. omdrop-awdl installs the Broadcom hooks from 0.10.0, the version the plugin pins, so core drives the radio directly once `omdrop install-driver` has updated the driver. Without them, `omdrop` uses the 0.9.x `omdrop-discoverable` instead. Either way, `omdrop install-driver` and `omdrop doctor` treat omdrop-awdl as the driver they manage: `doctor` reports a driver older than the one the plugin pins, and `install-driver` builds that one ([radio backends](../docs/radio-backend.md#omdrop-awdls-hooks)).

## How `omdrop` finds the other programs

Each lookup stops at the first match:

- **Sender:** `OMDROP_SENDER`; `send-to-peer` in the directory `omdrop` is in (`/usr/lib/omdrop-core/` in the package, the target directory in a development build); `/usr/lib/omdrop/send-to-peer`; `PATH`.
- **Root helper:** `OMDROP_DISCOVERABLE`; `/usr/lib/omdrop-core/omdrop-radio` if `/usr/lib/omdrop/radio/` exists; `/usr/lib/omdrop/omdrop-discoverable`.
- **Receiver:** `omdrop-receiver`, found like the sender; otherwise the plugin's `airdrop-serve.py`.
- **`omdrop` itself,** for the systemd units, notifications, desktop entries and the `~/.local/bin/omdrop` link: the plugin's `bin/omdrop`, so everything goes through the one entry point; without a plugin, core's own path.

`OMDROP_IMPLEMENTATION` chooses the stack: `python` uses the bash and Python programs throughout, for comparison; `rust`, or unset, uses these programs, falling back to a backend's own `omdrop-discoverable` when it ships no hooks. Any other value is refused (exit 2).

## Test

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Run the tests as an ordinary user, never as root or namespace root: `omdrop-radio`'s test seam is disabled for uid 0, and the identity code switches to root mode. Some tests need `openssl`, `dbus-daemon` and unprivileged user namespaces; tests that cannot set these up skip. Tests never touch Bluetooth, the real keyring or the live identity.

On a machine with a live `awdl0`, run the suite in its own network namespace, mapped back to a non-root uid:

```bash
unshare -rnm sh -c 'mount -t sysfs none /sys && ip link set lo up &&
  exec unshare --user --map-user=1001 --map-group=1001 cargo test --offline --workspace'
```

Keep `CARGO_TARGET_DIR` on disk. Where `/tmp` is tmpfs, a target directory there holds several gigabytes of RAM.

Interoperability with the Python programs, over loopback:

```bash
OMDROP_INTEROP_PY_SERVE=../bin/airdrop-serve.py \
OMDROP_INTEROP_RS_SERVE=target/debug/omdrop-receiver \
  cargo test -p omdrop-send --test interop
```

`crates/omdrop-radio/tests/python/` runs omdrop-awdl's privileged-input and supervisor tests against `omdrop-radio` and a mock backend.

Fuzzing: `fuzz/` has cargo-fuzz targets for the archive decoder, extraction, the plist parser and HTTP request parsing. The corpus and crash inputs stay local, out of the repository, because the marketplace's security scan cannot process them. The targets need a nightly toolchain:

```bash
cd fuzz && cargo +nightly fuzz run cpio_extract -- -max_total_time=300
```

## Licence

MIT. See [LICENSE](LICENSE).
