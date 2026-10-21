# Radio backends

Omdrop is two packages. This plugin is the panel, the `omdrop` command and the
receiver (`airdrop-serve.py`, on `awdl0`, TCP 8771). The **radio backend** makes
`awdl0` exist and makes this machine visible on it. The original backend is
[omdrop-awdl](https://github.com/netmojo-systems/omdrop-awdl), for the Broadcom
Wi-Fi in Apple Silicon Macs, whose firmware speaks AWDL.

Another backend can drive a different radio. For example,
[omdrop-owl](https://github.com/t4t5/omdrop-owl) runs AWDL in userspace through
OWL on a MediaTek MT7925, and
[omdrop-bcm4360](https://github.com/bydash-xyz/omdrop-bcm4360) runs it in
userspace over Broadcom's `wl` driver on Intel MacBooks with the BCM4360. The
plugin finds the backend's helpers in `/usr/lib/omdrop`, on `PATH`, or through
`OMDROP_DISCOVERABLE` and `OMDROP_SENDER`, and calls them as below.

This page describes the interface the bash and Python programs use. Omdrop
runs omdrop-core (`core/`) instead wherever the radio backend supports it:
today omdrop-awdl and omdrop-bcm4360, with omdrop-owl to follow once it ships
core's hooks (#73). Core uses the same `omdrop-discoverable` when a backend
ships nothing else. A backend can instead provide per-operation hooks in
`/usr/lib/omdrop/radio/`, as described in
[the backend contract](../core/docs/backend-contract.md); core then drives the
radio through them directly.

## `omdrop-discoverable`

Run as root through `pkexec` (polkit), except where noted. pkexec drops the
environment, so a helper works from fixed paths.

| Command | Does | Exit |
|---|---|---|
| `start <seconds>` | Become discoverable for that long (0: until stopped). Returns once `awdl0` carries a usable IPv6 link-local address. | 0, or 3 (can't now, retryable), 4 (no radio), 5 (already discoverable: the window was extended) |
| `stop` | Stop advertising and tear down. Never reload the Wi-Fi driver: that is not something a button may do behind someone's back. | 0 |
| `status [--json]` | Unprivileged. `{"visible":bool,"remaining":int\|null,"reason":str,"rx_proven":bool,"peer_op":str}` | 0 |
| `peers` | One line per AWDL peer heard: `<mac> rssi=<n>` (`rssi=?` when unknown). `send-to-peer` merges in the permanent IPv6 neighbours on `awdl0`. | 0, or 4 (radio down) |
| `probe --json` | Optional and unprivileged; see below. | 0 |

The backend also provides `send-to-peer`, which `omdrop send` and `omdrop peers`
call. omdrop-awdl's needs nothing from Broadcom, so another backend can ship it
unchanged next to its own `omdrop-discoverable`.

## `probe --json`

A backend that answers `probe` takes over the checks the plugin otherwise makes
for omdrop-awdl: Broadcom hardware, the `brcmfmac-awdl-dkms` package and its
version. A helper that doesn't answer (omdrop-awdl replies to an unknown command
with its usage and exit 2) gets those checks, unchanged.

```json
{
  "backend": "owl",
  "version": "0.1.0",
  "contract": "0.7.0",
  "hardware": true,
  "missing": [
    {"id": "radio", "say": "Wi-Fi isn't connected, and AirDrop shares its channel."}
  ]
}
```

It must answer within 5 seconds. A helper that doesn't is reported as a
`backend` item ("The radio backend did not answer…") and nothing else, not
taken for omdrop-awdl, and `omdrop install-driver` refuses to run.

- `backend` (required), `version`: shown to people, for example by
  `omdrop install-driver` and in messages that ask for a newer backend. An
  answer without `backend` doesn't count as a probe.
- `contract`: the omdrop-awdl version whose helper contract this backend follows.
  It must be at least the plugin's minimum (`BACKEND_CONTRACT_MIN` in
  `bin/omdrop`, now 0.7.0); a backend below it, or naming none, gets a `backend`
  item that says so. Features gated on a driver version (keeping the identity in
  1Password needs 0.7.0) compare against this instead of the
  `brcmfmac-awdl-dkms` package. Newer helper features, such as sending links,
  are found by asking the sender, so they need no contract bump.
- `hardware`: false when this machine has no radio the backend can drive. Then
  only the `hardware` item from `missing` is shown, as for a non-Mac today.
- `missing`: what stands in the way, most fundamental first, as
  `{"id", "say"}`. `say` is one sentence for the person holding the laptop.

### Item IDs

`driver`, `library` and `service` belong to the plugin, and the panel acts on
them: it offers its install button for `driver` and `library`, and that button
runs `omdrop install-driver`, which can't fix anything of a backend's. A
backend's item under one of these IDs is shown as `backend-<id>`, without the
button. Use your own IDs instead, such as `radio`.

The plugin adds its own items after the backend's: `library` (the receiver's
packages) and `service` (the receiving service). It reports `backend` itself
when the probe doesn't answer or the contract is too old.

With any other probing backend, `omdrop install-driver` installs only what belongs to
the plugin: the receiver's packages, and its firewall rule when ufw is active.
The backend is a package of its own, installed before the plugin can ask it
anything, so messages that ask for a newer helper name the backend's package
instead of `omdrop install-driver`.

### omdrop-awdl's hooks

omdrop-awdl 0.10.0 and later answer `probe` through their hooks in
`/usr/lib/omdrop/radio/` as backend `awdl`, reporting `hardware` (no Broadcom
chip) and `radio` (brcmfmac not loaded). The plugin pins 0.10.0, so
`omdrop install-driver` brings an older driver up to one with hooks.
omdrop-core treats that backend as the driver `omdrop install-driver` manages,
as it does a helper that doesn't answer:

- `omdrop doctor` keeps the probe's items, `hardware` first and alone, and
  adds its own `driver` item, before the probe's, when the installed
  `brcmfmac-awdl-dkms` is older than the version the plugin pins. That item
  comes from Omdrop, not from the probe, so the panel offers its button; an
  item the probe names `driver` is still shown as `backend-driver`.
- `omdrop install-driver` builds the pinned driver when the installed one is
  older, as well as the receiver's packages and the firewall rule. It refuses
  with the probe's `hardware` sentence when `hardware` is false.
- Messages that ask for a newer helper say `omdrop install-driver`.

The plugin's own `bin/omdrop` asks `omdrop-discoverable`, which doesn't answer
`probe`, so it gives omdrop-awdl the Broadcom checks either way.
