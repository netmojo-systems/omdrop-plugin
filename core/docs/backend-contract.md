# Radio backend contract, version 1

`omdrop-radio` is omdrop's only root entry point. polkit action
`org.omarchy.omdrop.radio` runs it as root at `/usr/lib/omdrop-core/omdrop-radio`.
It owns everything that does not depend on the radio:

- argument validation;
- the `__supervise` token;
- the discoverability window and its run directory;
- `status` and its JSON;
- the advertisers (`omdrop-adv mdns|announce|ble`);
- the receive proof;
- stop and cleanup.

A **radio backend** does the rest: it makes `awdl0` exist, carry frames, and
publish our identity at the radio layer. It provides **hooks**: one
executable per hook in the fixed, root-owned directory

```
/usr/lib/omdrop/radio/<hook>
```

Backends conflict with each other at the package level, so only one is ever
installed. Hooks can be written in any language. Today's backends are
omdrop-awdl (Broadcom firmware AWDL on Apple Silicon Macs) and omdrop-owl,
from Owly (userspace AWDL through Owly's radio service, `owlyd`, on other Wi-Fi
cards; its hooks are D-Bus clients of `owlyd`).

## Summary

|Hook|argv|Called by|Timeout|Required|
|---|---|---|---|---|
|`probe`|`probe --json`|`omdrop-radio probe --json` (unprivileged), and `start`|5 s|yes|
|`up`|`up`|`start`|300 s|yes|
|`identity`|`identity`|`start`, after `up` succeeds|120 s|no|
|`peer-watch`|`peer-watch`|the supervisor, once per window; long-running|none (killed at window end)|no|
|`tick`|`tick <seq>`|the supervisor, every interval|60 s|no|
|`down`|`down <why>`|`stop`, window expiry, failed `start`|60 s|no|
|`peers`|`peers`|`omdrop-radio peers`|20 s|no|
|`diag`|`diag <seconds>`|`omdrop-radio diag [seconds]`|seconds + 60 s|no|
|`read`|`read <name> <len>`|`omdrop-radio read <name> [len]`|20 s|no|
|`trace`|`trace on\|off\|status`|`omdrop-radio trace [on\|off]`|10 s|no|

An optional hook may be absent, which means "nothing to do": `down` for a
radio that needs no teardown, `peer-watch` for one with no firmware peer
table. Absent diagnostic hooks (`peers`, `diag`, `read`, `trace`) make the
`omdrop-radio` command exit 4 with "not supported by this radio backend".

## How core runs a hook

### Trust

Core runs a hook only if both the hook file and the hook directory are owned
by root and are not writable by group or others (checked with `stat`, after
symlinks are followed). Otherwise core treats the hook as broken: it logs why
and exits 4, as if no backend were installed. Core never runs a hook through
a shell: it calls `execve` on the fixed path with the fixed argv below.

### Arguments

Every argument comes from a fixed list or from a value core has already
validated, so a hook never needs to quote or re-parse caller input. Hooks
should still re-validate, as defence in depth.

|Argument|Guarantee|
|---|---|
|`<seq>`|Canonical decimal, 1 to 2⁶³−1. `1` on a window's first interval.|
|`<why>`|One of `stopped`, `expired`, `start-failed`, `radio-lost`.|
|`<seconds>` (diag)|Canonical decimal, 0 to 600.|
|`<name>` (read)|Matches `^awdl_[a-z0-9_]+$`, or is exactly `ver` or `cap`. At most 64 bytes.|
|`<len>` (read)|Canonical decimal, 1 to 8192. Core passes 512 when the caller gave none.|
|`on`, `off`, `status` (trace)|Literal. A bare `omdrop-radio trace` passes `status`.|

"Canonical decimal" means no sign, no leading zero (except `0` itself), and
ASCII digits only.

### Environment

Hooks never inherit the caller's environment, and neither do the advertisers
or the supervisor. Core clears the environment and sets exactly:

|Variable|Value|
|---|---|
|`PATH`|`/usr/bin:/usr/sbin`|
|`LANG`|`C.UTF-8`|
|`OMDROP_CONF`|`/etc/omdrop`, the per-machine tunables directory. It may not exist.|
|`OMDROP_RUN_DIR`|`/run/awdl-discoverable`, the run directory (see "Run directory").|
|`OMDROP_RADIO_HOOKS`|`1`, this contract's version.|
|`PKEXEC_UID`, `SUDO_UID`|Passed through only if present in core's own environment and canonical decimal (at most 10 digits). They name the invoking user, whose AirDrop identity the radio advertises.|

A hook that needs anything else must find it at a fixed path. A hook must not
assume `HOME`, `USER` or a terminal.

The working directory is `/`, standard input is `/dev/null`, and the umask
is `022`.

### Process group, timeouts and cancellation

Core starts every hook in a new process group. When a hook outlives its
timeout, or the command running it is cancelled (`stop` cancels a `start`
that is still in `up`), core sends `SIGTERM` to the whole group, waits 2 s,
then sends `SIGKILL` to the group. A hook may trap `SIGTERM` to undo a
half-done step; it gets those 2 s. A hook that survives `SIGKILL` for 5 s
(uninterruptible sleep behind a hung driver) is logged as unkillable and
counted as timed out; core stops waiting for it.

Keep every helper a hook runs inside the hook's process group, or the group
kill misses it. GNU `timeout` moves its command into a group of its own
unless given `--foreground`.

While `start` or the supervisor runs a hook, it records the hook's process
group and its leader's start time in `hook.pgid`. If the supervisor is
killed outright, `stop` (or the next `start`) kills that group, after
checking that its leader is still the recorded process.

A hook may leave a long-lived process running (omdrop-owl before 0.4.0 started
the OWL daemon in `up`). That process must start its own session (`setsid`),
so the group kill on a later timeout does not reach it, and it must not keep
the hook's stdout or stderr open. Core stops reading a hook's output 1 s after
the hook exits, whether or not the pipes have closed. `down` must stop any
such process.

`start` as a whole returns within **900 s**, its bound for callers: a wait
for the driver's boot-time warm-up (180 s, only while it runs),
the window lock (10 s) and a wait for a closing window (90 s), then `probe`,
`up` and `identity` at their timeouts plus the kill grace above (8 s each),
and on a failure `down`. A caller must wait at least that long (`omdrop`
does), or it gives up on a start that was going to work. omdrop-radio's
`start_returns_within_the_contracts_bound` test keeps the sum under it.

### Output

- **stderr is the log.** Write one line per event. Core copies each line to
  its own stderr and appends it to `/run/awdl-discoverable/log`. It prefixes a
  UTC `HH:MM:SSZ ` timestamp unless the line already starts with one. Hooks
  must not write `log` themselves, or every line appears twice. Lines longer
  than 4 KiB are truncated; invalid UTF-8 is replaced.
- **On failure, the last stderr line is the sentence a person reads.** The
  panel shows the last line of `start`'s stderr, minus the timestamp. Put
  evidence above it, and keep paths and iovar names out of it.
- **stdout** is relayed verbatim to core's stdout for `probe`, `peers`,
  `diag`, `read` and `trace`, up to 1 MiB. Core reads `up`'s stdout as an
  optional JSON object (see `up`). It discards stdout from `identity`, `tick`
  and `down`. `peer-watch`'s stdout and stderr go to `peers.log` in the run
  directory.

### Exit codes

|Code|Meaning|
|---|---|
|0|Done.|
|2|Usage error: a core bug, never the user's. Core logs it and fails the command: `start` exits 3, the diagnostic commands exit 2.|
|3|Can't now; retrying may help, for example a parked data path or a Wi-Fi link still associating.|
|4|No radio, or the feature isn't supported: no driver, no interface, no `awdl_trace` parameter, no reply.|
|anything else|Treated as 3 by `start`, and as 4 by the diagnostic commands.|

A hook killed for its timeout counts as 3.

## Hooks

### `probe --json`

Describes the backend and what stands in its way. It must work without root
and must not change anything. `omdrop-radio probe --json` relays it to the
plugin's `omdrop doctor` (omdrop-plugin PR #25, `docs/radio-backend.md`).
`start` runs it as root, before `up`.

```json
{
  "backend": "awdl",
  "version": "0.10.0",
  "contract": "0.10.0",
  "hooks": 1,
  "hardware": true,
  "missing": [
    {"id": "radio", "say": "AirDrop's Wi-Fi driver is not loaded. Restart to load it."}
  ]
}
```

|Field|Type|Meaning|
|---|---|---|
|`backend`|non-empty string, required|Short name, shown to people.|
|`version`|string|The backend package's version.|
|`contract`|string|The omdrop-awdl helper contract version the backend follows, compared by the plugin with `vercmp` (PR #25).|
|`hooks`|integer, required|This contract's version. Core runs only a backend that says `1`.|
|`hardware`|boolean, required|`false` when this machine has no radio the backend can drive.|
|`missing`|array of `{"id","say"}`|Blockers, most fundamental first. `say` is one sentence for the person at the laptop. `driver`, `library` and `service` are reserved for the plugin.|

Core relays the hook's JSON verbatim (after it parses as an object with a
non-empty `backend`) and exits 0. On no backend, a broken hook, a timeout, or
an invalid answer it exits 4 with a reason on stderr. `start` refuses a
backend whose `hooks` is not 1, or whose `hardware` is false. It exits 4 with
the first `missing` sentence, or with a generic one.

`omdrop doctor` and `omdrop install-driver` treat backend `awdl` as the
Broadcom driver package that `install-driver` builds and updates. They add
their own `driver` item when that package is older than the plugin's pin
(`docs/radio-backend.md` in the plugin, "omdrop-awdl's hooks").

### `up`

Bring `awdl0` up so it transmits and has an IPv6 link-local address. Exit 0
only then.

Core calls it from `start`, after it holds the start lock, has found no live
window, and has killed any children a dead supervisor left. Just before, core
writes `rx_proven` = `0` and removes `rx_base`.

- **0:** `awdl0` exists, is up, transmits as far as the backend can tell, and
  has a link-local address. Core checks the address itself
  (`/proc/net/if_inet6`, link scope). If it is missing, the window does not
  open: reason `no_awdl0`, `down start-failed`, exit 4.
- **3:** retryable (parked data path, Wi-Fi not associated). Core writes
  reason `parked`, calls `down start-failed`, and exits 3.
- **4:** no radio. Core writes reason `no_awdl0`, calls `down start-failed`,
  and exits 4.

`up` never reloads the Wi-Fi driver: a reload costs minutes of Wi-Fi and is
not something a button may do behind someone's back. Recreating a missing
interface without a reload is fine, and omdrop-awdl does it.

stdout may hold one JSON object, or nothing. Every field is optional:

```json
{"announce": {"count": 64, "interval_us": 16400, "period_s": 3, "plain": true}, "mdns": false}
```

|Field|Range|Default|Effect|
|---|---|---|---|
|`announce.count`|1–256|40|Frames per announcer burst.|
|`announce.interval_us`|1000–1000000|20000|Gap between frames.|
|`announce.period_s`|1–60|6|Supervisor interval: the pause between bursts.|
|`announce.plain`|bool|false|`--plain`: the backend adds AWDL encapsulation itself (OWL).|
|`mdns`|bool|true|Run core's mDNS responder on `awdl0`.|

Core ignores an invalid or out-of-range value, logs it, and uses the
default.

### `identity`

Publish this machine's identity at the radio layer, for the window `up` just
opened. omdrop-awdl uses it for the election metric, the RSSI thresholds,
the PSF template, the `awdl_afs_pload` service TLVs and `aftxmode`. Called
once per `start`, right after `up` returns 0 and before the supervisor
starts. A non-zero exit is logged; the window still opens, as it always has.

### `peer-watch`

Long-running. The supervisor starts it once, as the child tagged `peers`
(stdout and stderr appended to `peers.log`), and records it in `pids`. At
window end core sends `SIGTERM` to its process group, then `SIGKILL` 1 s
later. omdrop-awdl `exec`s its peer watcher, which registers peers in the
firmware's peer table and frees its slots on `SIGTERM`. If the hook exits
early, core logs it and doesn't restart it.

### `tick <seq>`

Called every supervisor interval (6 s by default), before the receive check
and the announcer burst. omdrop-awdl re-asserts a dropped link and rewrites
the PSF template when the election moves. Keep it short: the window does not
announce while it runs.

- **4:** the radio is gone. Core ends the window: it kills the children,
  writes reason `no_awdl0`, removes `until`, and calls `down radio-lost`.
- **Anything else, or a timeout:** logged; the window continues.

### `down <why>`

Undo `up`. Called after the window's children are gone: by `stop` (`stopped`),
at expiry (`expired`), when the radio is lost (`radio-lost`), and after a
failed `up` or any failure after it in `start` (`start-failed`). It must be idempotent,
because `stop` calls it even when no window is open. It never reloads the
driver. omdrop-awdl ships none: a stop has never touched its radio.

### `peers`

stdout, for people and for `send-to-peer`: every peer the radio hears on a
line that contains its MAC (`aa:bb:cc:dd:ee:ff`, lower-case hex) followed by
whitespace and `rssi=<n>`, with optional spaces after `=` and `?` when the
strength is unknown. Parsers match
`([0-9a-f]{2}(:[0-9a-f]{2}){5})\s+rssi=\s*(-?\d+|\?)` anywhere in a line and
ignore every other line. omdrop-awdl prints a header and extra fields per
peer (`rssi= -50/-52  aw_counter=... top=... dist=...`), and omdrop-owl prints
`<mac> rssi=?`. Exit 0, or 4 with the reason on stderr. A JSON form is planned
for v2 (see "Changes from the plan's draft").

### `diag <seconds>`

Read-only receive-side diagnostics, sampled over `<seconds>`; output is for
people. It must not issue a SET or toggle anything, so it is safe inside a
live window.

### `read <name> <len>`

One read-only GET, printed for people. Core applies the allowlist (AWDL
state, `ver` and `cap`; never credentials such as `wsec_key`). The hook must
apply it again. Exit 4 for no reply.

### `trace on|off|status`

Switch the per-frame transmit log on or off, or report it. stdout:
`awdl_trace=<n>`. Exit 4 when the radio has no such switch.

## Run directory

`/run/awdl-discoverable`, root-owned, mode 0755. `omdrop-radio` creates it.
`status` reads it without root, so everything except the token is
world-readable.

Core enforces this. It opens the directory with `O_DIRECTORY|O_NOFOLLOW` and
checks the descriptor:

- a symlink, or a directory owned by anyone but root: refused, exit 3;
- writable by group or others: reset to 0755, and logged. Every entry that
  is not a trusted regular file is then removed, through the descriptor;
  planted directories go recursively, without following links.

Every file operation is then relative to that descriptor (`openat` with
`O_NOFOLLOW`, `renameat`, `unlinkat`). A state file counts only when it is a
regular file, owned by root, not writable by group or others, and with a
single link. Anything else in its place, a symlink, a hard link or a
directory included, reads as absent and is removed or replaced. The
directory is shared with omdrop-awdl 0.9.x's
omdrop-discoverable, which creates files with its caller's umask; without
these checks, a user who could write the directory could make root kill a
process (through `pids`) or write a file anywhere (through a symlink).

|File|Owner|Content|
|---|---|---|
|`log`|core|Every log line, timestamped. Hooks write stderr, never this file.|
|`until`|core|Deadline in epoch seconds, or `0` for "until stopped". Written atomically. Absent means no window.|
|`reason`|core|`ok`, `parked`, `no_awdl0`, `stopped`, `expired`.|
|`rx_proven`, `rx_base`|core|The receive proof: `awdl0`'s `rx_packets` at window start, and whether it has moved since.|
|`supervisor`|core|`<pid> <start time>` of the supervisor (start time: field 22 of `/proc/<pid>/stat`).|
|`pids`|core|One `<pid> <tag> <start time>` line per window child, each the leader of its own process group.|
|`supervisor.token`, `start.lock`, `window.lock`, `pids.dying.*`, `hook.pgid`|core|Supervisor lifecycle. The token is mode 0600.|
|`announce`|core|`up`'s announce settings, validated.|
|`mdns.log`, `ble.log`, `peers.log`|core|Children's output.|
|`warmup.lock`|backend|Held by the driver's boot-time warm-up while it runs. Core only takes it shared, for an instant, to look.|
|`peerop.degraded`|backend|Present while registering a peer with the radio fails. `status` then reports `peer_op` `degraded`, and reason `peer_op_failed` instead of `ok`.|
|anything else|backend|Backend state, for example omdrop-awdl's `election.*`, `*.bin`, `diag.*`, `read.*`, `advertisers.*`. Core never reads these files.|

A backend must not write core's files. A backend that writes its own files
there as root should create them with `mktemp` or `O_EXCL|O_NOFOLLOW`, never
by a fixed name after `rm -f`.

## What core does

The point of the split is that these behaviours are written, reviewed and
tested once, in Rust, for every backend:

- Argument validation, before any work and before root is checked:
  - `start <seconds>`: canonical decimal, at most 9 digits; `0` means until
    stopped.
  - `__supervise <deadline> <seconds>`: the deadline has at most 12 digits.
  - `diag`: at most 600.
  - `read`: the allowlist above, and a length of at most 8192.
  - `trace`: `on`, `off` or `status`.
  - `status`: `--json`, or nothing.
  - `probe`: `--json`.
  - Anything else, including extra arguments: usage, exit 2.
- `__supervise` runs only with the 128-bit token `start` wrote to
  `supervisor.token` (0600). Core passes the token in the child's
  environment, which pkexec strips from a direct call.
- One start at a time (`flock` on `start.lock`, else exit 5). A second
  `start` during a live window moves its deadline (exit 5). The exception is
  the driver's boot-time warm-up. It holds `warmup.lock` whenever it holds
  `start.lock`, taking it first and letting go of it last. A start that finds
  `start.lock` held and `warmup.lock` held too waits up to 180 s, and exits 3
  if `start.lock` never comes free; with `warmup.lock` free it tries
  `start.lock` once more, for a warm-up that let go of both in between, and
  otherwise exits 5.
- The supervisor decides to end its window (expiry, `stop`, the radio lost)
  under `flock` on `window.lock`, and removes `until` before anything else;
  on expiry it re-reads `until` under the lock, so a deadline a second
  `start` moved keeps the window open. A `start` reads and moves the deadline
  under the same lock. One that finds the supervisor alive but `until` gone
  never reports an extension: it waits for that supervisor to exit (at most
  90 s, else exit 3) and then opens a new window.
- One supervisor per window, in its own session. It is alive only if the
  process at the recorded pid has the recorded start time, runs as root, and
  has argv `omdrop-radio __supervise ...`. That argv is matched by position:
  argv[0] must be the executable and argv[1] the verb, and as root
  `/proc/<pid>/exe` must be the executable too. Its children (the mDNS
  responder, `peer-watch`, the BLE wake advert) each run in their own process
  group, recorded in `pids`; a child that cannot be recorded is killed at
  once. Teardown is atomic: a `rename` of `pids` decides who runs it.
- Core signals a recorded child only when it can prove the process is the
  one it started:
  - for a `pids` line with a start time, the leader of that process group
    still has that start time and runs as root;
  - for a line without one (0.9.x's format), the process runs as root and is
    running the program for its tag.

  At window end the supervisor also kills every child it still holds, then
  waits at most 5 s for them.
- `stop` is idempotent. It TERMs every `start` still in `up` and every
  supervisor, through pidfds, so a reused pid is never signalled. Where
  pidfds are unavailable (ENOSYS, EPERM), it logs that and signals by pid,
  re-checking the start time, argv and uid immediately before each signal.
  It waits for them and KILLs any supervisor still alive after 10 s. Then
  it kills an orphaned hook (`hook.pgid`): TERM to the group, then KILL to
  whatever of it remains. It calls `down stopped` and writes reason
  `stopped`.
- A failed `start` leaves nothing behind: no supervisor, token, `until`, or
  children, and `down start-failed` has run.
- A live omdrop-awdl 0.9.x supervisor counts as a live window, because both
  helpers share the run directory. It counts only when argv is
  `bash /usr/lib/omdrop/omdrop-discoverable __supervise ...` by position,
  it runs as root, and it is the pid 0.9.x recorded in `supervisor` (or a
  subshell of it):
  - `status` reports it;
  - `start` exits 5 without touching it or its children;
  - `stop` ends it.
- The receive proof (`rx_proven`) comes from `awdl0`'s `rx_packets` counter,
  which works for any netdev.
- avahi's conflict rename of the host name is undone every tenth interval
  and on `stop`.

## Conformance

`crates/omdrop-radio/tests/mock-backend/` is a backend made of shell scripts
that implements this contract against a fake `awdl0`. The conformance tests in
`crates/omdrop-radio/tests/` run `omdrop-radio` against it without root.

**The test seam.** `omdrop-radio` reads `OMDROP_RADIO_TEST_ROOT` only when
its real and effective uids are both non-zero, and the kernel did not mark
the exec secure (`AT_SECURE`: setuid, setgid or file capabilities). The
variable relocates every fixed path under that directory:

- the hooks, the run directory and `/etc/omdrop`;
- `/sys/class/net`, `/proc/net/if_inet6` and the host name;
- `busctl` and `avahi-set-host-name`;
- 0.9.x's `/usr/lib/omdrop`.

It also waives the root check, and every ownership check (hooks, run
directory, state files, process uids) then expects the caller's uid. Under
pkexec, core runs as uid 0 and ignores the variable. `pkexec --user <someone>`
runs it as that user, but pkexec strips the environment, so the variable
never arrives. A process that honours it already runs with its caller's own
privileges, so the seam can only redirect what that user could run directly.
Core passes the variable to hooks and children only while it honours it.

A backend conforms when, with its hooks installed and on its hardware:

1. `probe --json` answers within 5 s without root, as an object with
   `backend`, `hooks: 1` and `hardware`.
2. `up` exits 0 only with `awdl0` up and a link-local address present; 3 or 4
   otherwise, the last stderr line a sentence for people.
3. Every hook exits within its timeout, never reads stdin, and needs nothing
   from the environment beyond the variables listed above.
4. `up` survives `SIGTERM` mid-run without leaving the radio worse than a
   later `up` can repair.
5. `down` is idempotent and safe with no window open.
6. No hook writes core's run-directory files.
7. `peer-watch` exits on `SIGTERM`.

Core-side conformance, which every backend gets without writing a test:

- `cargo test -p omdrop-radio` runs it against the mock backend.
- `python3 -m unittest discover -s crates/omdrop-radio/tests/python` runs
  omdrop-awdl's privileged-input and supervisor-lifecycle suites, adapted to
  drive the binary.

## Changes from the plan's draft

- `service-record <file>` became `identity`. omdrop-awdl builds its service
  TLVs from its own identity code (`mkpsf.py --service-only`), and omdrop-owl
  needs no record at the radio layer. Core takes over building the record once
  the identity crate can produce it (v2).
- `peer-add <mac>` became the long-running `peer-watch`. Registration follows
  what the radio hears, not anything core knows.
- `peers` keeps today's text, because `send-to-peer` and the CLI parse it.
  `peers --json` is reserved for v2.
- Added `tick` (template upkeep), `identity` (identity writes), and `diag`,
  `read` and `trace` (diagnostics that need root).
- Added `hooks` to the probe, and the optional announce settings to `up`'s
  stdout. omdrop-owl announces in plain mode with its own burst, and only
  knows which burst after `up` has picked shared or exclusive mode.
