# Notes for coding agents

Read [CONTRIBUTING.md](CONTRIBUTING.md) before making any code change. It lists what a pull request needs: the problem, your setup, evidence from real hardware, and tests. Those rules apply to agents as much as to people.

## A migration is in progress

Omdrop is moving from bash and Python to Rust. **All new development goes into the Rust version in `core/`.** Until 1.0.0, this repository still holds both implementations of the same programs:

|Program|Bash and Python (fallback)|Rust, in `core/`|
|---|---|---|
|The `omdrop` command|`bin/omdrop`, `bin/pick.py`|`core/crates/omdrop-cli`|
|The receiver|`bin/airdrop-serve.py`|`core/crates/omdrop-receiver`|
|Identity and Contacts Only|`bin/identity.py`, `bin/contacts.py`|`core/crates/omdrop-identity`, `core/crates/omdrop-proto`|
|Sender, advertisers, root helper|in the radio backend (omdrop-awdl, omdrop-owl)|`core/crates/omdrop-send`, `omdrop-adv`, `omdrop-radio`|

The panel (`Panel.qml` and the other QML files), the agent skill (`skills/`) and the link handler belong to the plugin only; they have no Rust counterpart.

Omdrop runs the Rust version wherever the radio backend supports it, and the bash and Python programs elsewhere. Today that is omdrop-awdl and omdrop-bcm4360; omdrop-owl follows once it ships core's hooks (#73). With a supported backend, `omdrop setup` and `omdrop doctor` offer core, `omdrop install-core` installs it, and the plugin then hands it every command.

Epic #73 tracks the migration. Rust becomes the only implementation in 1.0.0, once this plugin, omdrop-awdl and omdrop-owl all run on it.

## Rules during the migration

- **Change the Rust version only.** The bash and Python programs remain as the fallback for installs without omdrop-core and are not developed further; don't add features to them or port changes back. There are two exceptions. A security fix is accepted for the Python too, since installs without core still run it. Installing core (`omdrop install-core`, and `doctor` offering it) lives in `bin/omdrop`, because it runs before core exists; core's `install-core` runs that one. The bash and Python programs are removed at 1.0.0.
- **Keep the Rust programs drop-in.** Each replaces a current program with the same arguments, output, files and exit codes, because the panel and existing installs depend on them.
- **Test in `core/`:** `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check`. Run them as an ordinary user, never as root. If you touch the plugin side (`bin/omdrop`'s hand-off, the QML), also run the Python suite from the repository root: `python3 -m unittest discover -s tests`.
- **Know which stack you are running.** `bin/omdrop` is the one entry point: core's package puts its `omdrop` at `/usr/lib/omdrop-core/omdrop`, off `PATH`. When that core reports at least `CORE_MIN` (in `bin/omdrop`) and the radio backend ships core's hooks (`/usr/lib/omdrop/radio/probe`), `bin/omdrop` hands every command to it, including the command-line tests. An older core, one whose version can't be read, or a backend without hooks gets none. `OMDROP_IMPLEMENTATION=python` keeps the bash and Python programs; `rust` requires a core at least `CORE_MIN` and a backend with hooks.
- **The `omdrop` package** (`omarchy-pkgs/pkgbuilds/omdrop/`, for omacom/omarchy-pkgs) installs the plugin at `/usr/share/omdrop`, core at `/usr/lib/omdrop-core`, and `/usr/bin/omdrop` as a link to the plugin's `bin/omdrop`, never to core. `setup` links the packaged plugin into `~/.config/omarchy/plugins`, asking before it replaces another copy. Update the recipe's `pkgver` with each release.
- **Never run core from this checkout as root, and never point a polkit action or a systemd unit at it.** Core is built and installed as its own package (`omdrop install-core`, or `makepkg -si` in `core/`). Its root helper must sit at a fixed, root-owned path, or any user could gain root through it.
- **Bump `core/PKGBUILD`'s `pkgver` or `pkgrel` in any release that changes `core/`.** It is how `install-core` and `doctor` tell an installed core is older than the plugin's.
- **Raise `CORE_MIN` in `bin/omdrop` when the plugin starts relying on something new in core,** together with a `pkgver` bump in `core/PKGBUILD` and `core/Cargo.toml`. Core reports only its `pkgver`, so a `pkgrel` bump can't be required.
- **Pin the omdrop-awdl driver in both stacks at once:** `DRIVER_COMMIT`, `DRIVER_VERSION` and the literal commit in the build script, in `bin/omdrop` and in `core/crates/omdrop-cli/src/driver.rs`. Core runs `install-driver`, so a new pin also needs a core `pkgver` bump and `CORE_MIN` raised to it.
- **Radio backends talk to core through hooks**, described in `core/docs/backend-contract.md`. Hooks ship with the backend (omdrop-awdl, omdrop-owl), not with core. A change to the contract affects every backend, so propose it in an issue first.

## Safety

- **Don't touch a live radio.** Tests must not depend on the machine they run on, and must not transmit. The Rust tests that run the real sender do so in a private network namespace and skip where one is unavailable; keep it that way.
- **The receiver handles untrusted input.** Anything nearby can send to it in Everyone mode. A change there must keep the existing size, member and disk limits, and say what a hostile sender could do with the new code path (CONTRIBUTING.md, "Receiver changes").
- **Logs and dumps can identify people.** Follow CONTRIBUTING.md, "Before you share logs", before pasting any into an issue or pull request.
