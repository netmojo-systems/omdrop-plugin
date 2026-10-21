# Contributing to Omdrop

Bug reports and pull requests are welcome. Omdrop's behaviour depends on Apple devices, Wi-Fi hardware, and radio backends that reviewers often can't reproduce, so a pull request is reviewed on the evidence it includes. This page lists what to include.

## What a pull request needs

Describe what the change does, then provide each of the following that applies.

### The problem

- What happened, and what you expected instead.
- How often it happens: for example, "4 of 7 transfers ended in a 408".
- Which claims you measured and which you inferred. "The iPhone never sends the closing chunk" needs a log line or capture. Without one, say it's a guess.

### Your setup

Paste the whole output of this command. It reports the computer's model, Wi-Fi chip, kernel, radio backend, Omdrop's version and readiness, the identity in use, the Wi-Fi firmware, and `awdl0`. omdrop-awdl's hardware-report form asks for the same details.

```bash
{ tr -d '\0' < /proc/device-tree/model 2>/dev/null || cat /sys/class/dmi/id/product_name; echo; lspci -nn | grep -i network; uname -r; pacman -Q brcmfmac-awdl-dkms omdrop-bcm4360 omdrop-owl; omdrop --version; omdrop doctor --json; omdrop identity; journalctl -k -b | grep -m1 'brcmfmac.*Firmware:'; ip -br link show awdl0; } 2>&1
```

One of the two radio backend packages is reported as not found; that's expected.

Also give:

- Each Apple device involved: its model and OS version, such as "iPhone 15 Pro, iOS 26.1".
- The visibility mode on each side (Everyone or Contacts Only).
- For panel or QML changes: `pacman -Q qt6-declarative quickshell` and your Omarchy version.

### Evidence from real hardware

If the change affects how Omdrop talks to an Apple device, show the behaviour before and after the change on real hardware. Paste text, not screenshots, and include the lines that show the behaviour you describe.

| What changed | Where to get the evidence |
|---|---|
| Receiving | `journalctl --user -u airdrop-receiver --since "15 min ago"`. Useful lines include `ask from …`, `upload …: decoded to N bytes, magic …`, `stored …`, and the HTTP status of each request. |
| Sending | The output of `omdrop send --verbose …`. It also writes protocol dumps to `$XDG_RUNTIME_DIR/omdrop/debug`, with validation records and certificates replaced by their size. |
| The radio | The radio backend's log. For omdrop-awdl, that's `/run/awdl-discoverable/log` during the window. |
| A new content type, header, or protocol field | The receiver log line showing what the device actually sent. A test that builds the input itself shows that the code accepts it, not that a real device sends it. |

### Tests

- Run `python3 -m unittest discover -s tests` on current `main` and on your branch. Report both counts.
- Name every test that fails, and say whether it also fails on `main`.
- Add a regression test that fails without your change and passes with it. Use real sockets and real TLS where the existing tests do. A test must not depend on the machine it runs on.
- With omdrop-core installed (`/usr/lib/omdrop-core/omdrop`), `bin/omdrop` hands every command to it, so the command-line tests then exercise core. Run them with `OMDROP_IMPLEMENTATION=python` to test the bash script.

### omdrop-core

`core/` holds omdrop-core, the same programs in Rust, as one Cargo workspace. Omdrop runs it wherever the radio backend supports it; today that is omdrop-awdl and omdrop-bcm4360, and omdrop-owl follows once it ships core's hooks (#73). Other backends run the bash and Python programs. Core builds and installs as its own package; nothing in it runs from the plugin's clone. Users install it with `omdrop install-core`, which `omdrop setup` and `omdrop doctor` offer with a supported backend, and which builds this `core/` with makepkg when no repository carries its version. Its tests run as an ordinary user, never root:

```bash
cd core
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

`core/README.md` covers the programs and how they find each other, and `core/docs/backend-contract.md` the hooks a radio backend provides.

`core/PKGBUILD`'s `pkgver` and `pkgrel` are how `omdrop install-core` and `omdrop doctor` tell whether an installed core matches the plugin. Bump one of them in any release that changes `core/`, or users keep the older core.

`bin/omdrop` hands commands only to a core at least `CORE_MIN`, which it reads from the installed core's own `omdrop version` line rather than from pacman. Below that, or when the version can't be read, it runs the bash and Python programs, and `doctor` says the core is too old and names what updates it. When the plugin starts relying on something new in core, raise `CORE_MIN` to that version, and bump `pkgver` in `core/PKGBUILD` and `core/Cargo.toml` together. A `pkgrel` bump alone doesn't change the version core reports.

The omdrop-awdl driver is pinned in both stacks: `DRIVER_COMMIT` and `DRIVER_VERSION` in `bin/omdrop` and in `core/crates/omdrop-cli/src/driver.rs`, each with the commit also written literally in its build script. Change them together, in one commit. Because core runs `omdrop install-driver` once it is installed, a new driver pin also needs a core version bump and `CORE_MIN` raised to it, or an older core keeps building the older driver.

New development goes into `core/` only. The bash and Python programs remain as the fallback for installs without omdrop-core, are not developed further, and will be removed at 1.0.0, so a pull request that changes them will usually be asked to make the change in Rust instead. There are two exceptions. Security fixes for the bash and Python programs are welcome, because installs without omdrop-core still run them. Installing omdrop-core (`omdrop install-core`, and `doctor` offering it) lives in `bin/omdrop`, because it has to run before core exists; core's own `install-core` runs that one.

### Receiver changes

The receiver accepts connections from any nearby device in Everyone mode, and an `/Upload` needs no accepted Ask first. For a change to the receiver, explain:

- What a hostile sender can do with the new code path: for example, trickle bytes, stall, or send a malformed body.
- What it costs: CPU, memory, disk, and how often that cost can be triggered.
- That the existing size, member, and disk limits still apply.

### Your branch

- Base it on current `main`, and rebase when `main` moves. Git can merge two changes to the same file without a conflict and still break both, so run the tests again after rebasing.
- Make one change per pull request.
- Author your commits as yourself. Add someone else as an author or co-author only with their agreement.

## Before you share logs

Logs and dumps can identify people. Before posting:

- **Remove device names.** Lines such as `ask from …` and `serving … as …` carry device names, which often include a person's name.
- **Remove contact details.** Apple ID email addresses, phone numbers, and the known-senders list.
- **Remove network identifiers.** Your router's MAC address and network name. AWDL addresses rotate each session and are fine to share.
- **Never share identity material.** That includes anything in `~/.omdrop/keys`, `validation_record.cms`, 1Password items, and the output of `op`.

## Reporting a bug

[Open an issue](https://github.com/netmojo-systems/omdrop-plugin/issues) with the problem, your setup, and the evidence described above.
