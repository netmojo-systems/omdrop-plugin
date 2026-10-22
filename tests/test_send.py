import json
import os
import plistlib
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OMDROP = ROOT / "bin" / "omdrop"

# What send-to-peer --list reports: address, signal, endpoint.
ONE_PEER = "e2:9d:03:6c:58:23   -47 dBm  [fe80::e09d:3ff:fe6c:5823%awdl0]:8770"
THREE_PEERS = "\n".join(
    [
        "fe:63:e6:68:9f:12   -14 dBm  [fe80::fc63:e6ff:fe68:9f12%awdl0]:8770",
        "16:2f:da:27:3d:76   -33 dBm  [fe80::142f:daff:fe27:3d76%awdl0]:8770",
        ONE_PEER,
    ]
)

# What airdrop-send.py logs for a transfer the device accepted and stored.
SENT = (
    "2026-09-18 12:00:00,000 INFO send: +  0.41s FOUND 0e9d036c5823 'hume' "
    "at [fe80::e09d:3ff:fe6c:5823%awdl0]:8770; asking\n"
    "2026-09-18 12:00:02,000 INFO send: +  2.10s ASK -> accepted (1.69s)\n"
    "2026-09-18 12:00:02,600 INFO send: +  2.72s UPLOAD photo.jpg -> ok "
    "(2493 B, 0.62s)"
)
DECLINED = (
    "2026-09-18 12:00:00,000 INFO send: +  0.41s FOUND 0e9d036c5823 'hume' "
    "at [fe80::e09d:3ff:fe6c:5823%awdl0]:8770; asking\n"
    "2026-09-18 12:00:04,000 INFO send: +  4.02s ASK -> declined (3.61s)"
)


class SenderFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.bin = root / "bin"
        self.bin.mkdir()
        self.capture = root / "capture"
        self.capture_list = root / "capture-list"
        self.file = root / "photo.jpg"
        self.file.write_bytes(b"\xff\xd8\xff" + b"0" * 64)

        config = root / "config" / "airdrop"
        config.mkdir(parents=True)
        (config / "config.toml").write_text('name = "Study Mac"\n')

        # Stands in for send-to-peer: records how it was called, answers
        # --list from PEER_LIST, and replays a sender log for a transfer.
        self.sender = self.command(
            "send-to-peer",
            """#!/bin/sh
if [ "$1" = --help ]; then
  if [ -n "$HELP_SLEEP" ]; then trap '' TERM; sleep "$HELP_SLEEP"; : > "$CAPTURE_LIST.outlived"; fi
  printf '%s\\n' "${SENDER_USAGE-  -n, --names  [file ...]}"
  exit 0
fi
out="$CAPTURE"
[ "$1" = --list ] && out="$CAPTURE_LIST"
: > "$out"
for arg do printf '%s\\n' "$arg" >> "$out"; done
if [ "$1" = --list ]; then
  [ -n "$LIST_RC" ] && { echo "could not read the peer table" >&2; exit "$LIST_RC"; }
  # Both a silent pipe and EOF can come from a lookup that is still alive.
  if [ -n "$LIST_SLEEP" ]; then
    trap '' TERM
    [ -z "$LIST_CLOSE_OUTPUT" ] || exec >/dev/null 2>&1
    sleep "$LIST_SLEEP"
    : > "$CAPTURE_LIST.outlived"
  fi
  if [ -n "$PEER_LIST_LATER" ] && [ -e "$CAPTURE_LIST.asked" ]; then
    printf '%s\\n' "$PEER_LIST_LATER"; exit 0
  fi
  : > "$CAPTURE_LIST.asked"
  [ -n "$PEER_LIST" ] || exit 1
  printf '%s\\n' "$PEER_LIST"
  if [ -n "$LIST_POST_SLEEP" ]; then
    trap '' TERM
    [ -z "$LIST_CLOSE_OUTPUT" ] || exec >/dev/null 2>&1
    sleep "$LIST_POST_SLEEP"
    : > "$CAPTURE_LIST.outlived"
  fi
  if [ -n "$PEER_LIST_TAIL" ]; then
    sleep "${LIST_TAIL_DELAY:-0}"
    printf '%s\\n' "$PEER_LIST_TAIL"
  fi
  exit 0
fi
[ -n "$SENDER_STDOUT" ] && printf '%s\\n' "$SENDER_STDOUT"
[ -n "$SENDER_STDERR" ] && printf '%s\\n' "$SENDER_STDERR" >&2
# A sender still waiting for the device, which leaves a mark if it outlives
# the send that started it. It ignores TERM, as the real one can.
if [ -n "$SENDER_SLEEP" ]; then trap '' TERM; sleep "$SENDER_SLEEP"; : > "$CAPTURE.outlived"; fi
exit "${SENDER_RC:-0}"
""",
        )
        # The radio's address is the precondition for any transfer, so the
        # tests own what `ip` reports about it.
        self.command(
            "ip",
            """#!/bin/sh
[ "${RADIO:-up}" = up ] || exit 0
echo "    inet6 fe80::1c9a:4bff:fe33:1/64 scope link"
""",
        )
        # Whether a window is open is the radio helper's to say: awdl0 keeps
        # its address after `omdrop off`. WINDOW_JSON replaces the answer.
        self.discoverable = self.command(
            "omdrop-discoverable",
            """#!/bin/sh
[ -n "$WINDOW_JSON" ] && { printf '%s\\n' "$WINDOW_JSON"; exit 0; }
if [ "${WINDOW:-${RADIO:-up}}" = up ]; then echo '{"visible":true}'; else echo '{"visible":false}'; fi
""",
        )
        # A send that turns Omdrop on runs `omdrop on`, which starts with
        # systemd. This one refuses everything and records that it was asked,
        # so activation fails inside the sandbox: HOME is the temporary
        # directory, so nothing is written to the real one.
        self.systemctl_log = root / "systemctl.log"
        self.command(
            "systemctl",
            """#!/bin/sh
printf '%s\\n' "$*" >> "$SYSTEMCTL_LOG"
exit 1
""",
        )

        self.env = os.environ.copy()
        for key in ("XDG_DATA_HOME", "XDG_BIN_HOME"):
            self.env.pop(key, None)
        self.env.update(
            HOME=str(root),
            PATH=f"{self.bin}:{self.env['PATH']}",
            CAPTURE=str(self.capture),
            CAPTURE_LIST=str(self.capture_list),
            XDG_CONFIG_HOME=str(root / "config"),
            SYSTEMCTL_LOG=str(self.systemctl_log),
            OMDROP_SENDER=str(self.sender),
            OMDROP_DISCOVERABLE=str(self.discoverable),
            PEER_LIST=ONE_PEER,
            SENDER_STDOUT=SENT,
            LIST_RC="",
            SENDER_RC="",
            # bash counts this wait in whole seconds of the clock (see
            # start_on_a_clock_tick), so a lookup that is meant to finish gets
            # room to; the tests that time the deadline set their own.
            OMDROP_NAME_WAIT="30",
            LIST_SLEEP="",
            LIST_POST_SLEEP="",
            LIST_CLOSE_OUTPUT="",
            HELP_SLEEP="",
            PEER_LIST_LATER="",
            PEER_LIST_TAIL="",
            LIST_TAIL_DELAY="",
        )

    def command(self, name, body):
        path = self.bin / name
        path.write_text(body)
        path.chmod(0o755)
        return path

    def run_omdrop(self, *args):
        return subprocess.run(
            [OMDROP, *args], env=self.env, capture_output=True, text=True
        )

    def sender_args(self):
        return self.capture.read_text().splitlines()


class SendLinkTests(SenderFixture):
    def setUp(self):
        super().setUp()
        self.env["SENDER_USAGE"] = "  -n, --names  --url URL  [file ...]"
        self.env["SENDER_STDOUT"] = (
            "2026-10-09 12:00:00,000 INFO send: +  1.21s ASK -> accepted (0.13s)\n"
            "2026-10-09 12:00:00,000 INFO send: +  1.21s LINK https://example.com/ -> ok"
        )

    def test_web_addresses_are_passed_unchanged_as_repeated_url_options(self):
        urls = ["http://example.com/", "HTTPS://example.com/a?q=1&b=2#section"]

        result = self.run_omdrop("send", "--to", "6c:58", *urls)

        self.assertEqual(result.returncode, 0, result.stderr)
        args = self.sender_args()
        self.assertEqual(args[args.index("--url"):], ["--url", urls[0], "--url", urls[1], "--"])
        self.assertEqual(args[args.index("--mac") + 1], "e2:9d:03:6c:58:23")

    def test_a_recipient_can_come_before_or_after_a_link(self):
        self.env["PEER_LIST"] = f"{ONE_PEER}  Studio Mac"
        url = "https://example.com/"
        for payload in [("Studio Mac", url), (url, "Studio Mac")]:
            with self.subTest(payload=payload):
                result = self.run_omdrop("send", *payload)

                self.assertEqual(result.returncode, 0, result.stderr)
                args = self.sender_args()
                self.assertEqual(args[args.index("--url") + 1], url)
                self.assertEqual(args[args.index("--mac") + 1], "e2:9d:03:6c:58:23")

    def test_shortcuts_go_as_the_web_link_inside_them(self):
        url = "https://example.com/a.dmg"
        shortcuts = {
            "download.webloc": plistlib.dumps({"URL": url}),
            "binary.WEBLOC": plistlib.dumps({"URL": url}, fmt=plistlib.FMT_BINARY),
            "download.URL": f"[InternetShortcut]\r\nURL={url}\r\n".encode(),
        }
        for name, content in shortcuts.items():
            with self.subTest(name=name):
                shortcut = Path(self.tmp.name) / name
                shortcut.write_bytes(content)

                result = self.run_omdrop("send", str(shortcut))

                self.assertEqual(result.returncode, 0, result.stderr)
                args = self.sender_args()
                self.assertEqual(args[args.index("--url") + 1], url)
                self.assertEqual(args[args.index("--") + 1:], [])
                self.assertIn(f"Sending the link in {name}", result.stdout)

    def test_non_web_and_invalid_shortcuts_remain_files(self):
        shortcuts = {
            "share.webloc": plistlib.dumps({"URL": "smb://fileserver/share"}),
            "invalid.webloc": b"not a property list",
            "invalid.url": b"[OtherSection]\nURL=https://example.com/\n",
        }
        for name, content in shortcuts.items():
            with self.subTest(name=name):
                shortcut = Path(self.tmp.name) / name
                shortcut.write_bytes(content)

                result = self.run_omdrop("send", str(shortcut))

                self.assertEqual(result.returncode, 0, result.stderr)
                args = self.sender_args()
                self.assertNotIn("--url", args)
                self.assertEqual(args[args.index("--") + 1:], [str(shortcut)])

    def test_links_and_files_are_refused_before_discovery(self):
        shortcut = Path(self.tmp.name) / "page.url"
        shortcut.write_text("[InternetShortcut]\nURL=https://example.com/\n")
        for link in ["https://example.com/", str(shortcut)]:
            with self.subTest(link=link):
                result = self.run_omdrop("send", str(self.file), link)

                self.assertNotEqual(result.returncode, 0)
                self.assertIn("separately", result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertFalse(self.capture_list.exists())
                self.assertFalse(self.capture.exists())

    def test_a_driver_without_links_is_told_to_update_before_discovery(self):
        self.env["SENDER_USAGE"] = "  -n, --names  [file ...]"

        result = self.run_omdrop("send", "https://example.com/")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("omdrop install-driver", result.stderr)
        self.assertFalse(self.capture_list.exists())
        self.assertFalse(self.capture.exists())
        file_result = self.run_omdrop("send", str(self.file))
        self.assertEqual(file_result.returncode, 0, file_result.stderr)

    def test_a_delivered_link_is_reported_without_the_protocol_log(self):
        result = self.run_omdrop("send", "https://example.com/")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Sent https://example.com/", result.stdout)
        self.assertNotIn("INFO send", result.stdout)

    def test_a_declined_link_preserves_the_sender_exit_status(self):
        self.env["SENDER_STDOUT"] = DECLINED
        self.env["SENDER_RC"] = "3"

        result = self.run_omdrop("send", "https://example.com/")

        self.assertEqual(result.returncode, 3)
        self.assertIn("declined", result.stderr)
        self.assertNotIn("Sent ", result.stdout)

    def test_verbose_link_sending_preserves_the_protocol_log(self):
        result = self.run_omdrop("send", "--verbose", "https://example.com/")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(self.env["SENDER_STDOUT"], result.stdout)

    def test_a_link_to_a_named_device_turns_omdrop_on_first(self):
        self.env["RADIO"] = "down"

        result = self.run_omdrop("send", "--to", "6c:58", "https://example.com/")

        self.assertIn("Turning it on", result.stdout)
        self.assertTrue(self.systemctl_log.exists(), "omdrop on was never run")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("could not be turned on", result.stderr)
        self.assertFalse(self.capture_list.exists())
        self.assertFalse(self.capture.exists())

    def test_ambiguous_peer_suggestions_include_the_link(self):
        self.env["PEER_LIST"] = THREE_PEERS

        result = self.run_omdrop("send", "https://example.com/")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("omdrop send --to fe:63:e6:68:9f:12 https://example.com/", result.stderr)
        self.assertFalse(self.capture.exists())


class SendCommandTests(SenderFixture):
    def test_send_names_this_computer_the_way_receiving_does(self):
        result = self.run_omdrop("send", str(self.file))

        self.assertEqual(result.returncode, 0, result.stderr)
        args = self.sender_args()
        self.assertEqual(args[-1], str(self.file))
        self.assertEqual(args[args.index("--name") + 1], "Study Mac")

    def test_send_waits_for_a_sleeping_receiver_by_default(self):
        self.run_omdrop("send", str(self.file))

        args = self.sender_args()
        self.assertEqual(args[args.index("--wait") + 1], "30")

    def test_the_only_device_heard_needs_no_address(self):
        self.run_omdrop("send", str(self.file))

        args = self.sender_args()
        self.assertEqual(args[args.index("--mac") + 1], "e2:9d:03:6c:58:23")

    def test_part_of_an_address_is_enough_to_choose_a_device(self):
        self.env["PEER_LIST"] = THREE_PEERS

        result = self.run_omdrop("send", "--to", "6C:58", str(self.file))

        self.assertEqual(result.returncode, 0, result.stderr)
        args = self.sender_args()
        self.assertEqual(args[args.index("--mac") + 1], "e2:9d:03:6c:58:23")

    def test_several_devices_heard_are_offered_in_this_commands_words(self):
        self.env["PEER_LIST"] = THREE_PEERS

        result = self.run_omdrop("send", str(self.file))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("omdrop send --to fe:63:e6:68:9f:12", result.stderr)
        # The sender's own word for --to is --mac; naming it here would point
        # at an option this command does not have.
        self.assertNotIn("--mac", result.stderr)
        self.assertFalse(self.capture.exists())

    def test_an_address_matching_several_devices_is_refused(self):
        self.env["PEER_LIST"] = THREE_PEERS

        result = self.run_omdrop("send", "--to", ":", str(self.file))

        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.capture.exists())

    def test_an_address_nobody_answers_to_is_refused(self):
        result = self.run_omdrop("send", "--to", "aa:bb:cc", str(self.file))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("omdrop peers", result.stderr)
        self.assertFalse(self.capture.exists())

    def test_an_empty_room_says_a_window_is_what_hears_devices(self):
        self.env["PEER_LIST"] = ""

        result = self.run_omdrop("send", str(self.file))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("omdrop on", result.stderr)
        self.assertFalse(self.capture.exists())

    def test_a_peer_table_that_cannot_be_read_is_not_an_empty_room(self):
        self.env["LIST_RC"] = "4"

        result = self.run_omdrop("send", str(self.file))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("could not read the peer table", result.stderr)
        self.assertNotIn("within earshot", result.stderr)

    def test_send_refuses_a_folder_without_sending(self):
        result = self.run_omdrop("send", str(self.file.parent))

        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.capture.exists())

    def second_file(self, name="notes.txt"):
        other = Path(self.tmp.name) / "elsewhere"
        other.mkdir(exist_ok=True)
        path = other / name
        path.write_text("notes\n")
        return path

    def test_several_files_go_to_the_sender_as_one_transfer(self):
        notes = self.second_file()

        result = self.run_omdrop("send", str(self.file), str(notes))

        self.assertEqual(result.returncode, 0, result.stderr)
        args = self.sender_args()
        self.assertEqual(args[args.index("--") + 1:], [str(self.file), str(notes)])

    def test_the_recipient_may_sit_anywhere_among_the_files(self):
        self.env["PEER_LIST"] = THREE_PEERS
        notes = self.second_file()

        result = self.run_omdrop("send", str(self.file), "6c:58", str(notes))

        self.assertEqual(result.returncode, 0, result.stderr)
        args = self.sender_args()
        self.assertEqual(args[args.index("--mac") + 1], "e2:9d:03:6c:58:23")
        self.assertEqual(args[args.index("--") + 1:], [str(self.file), str(notes)])

    def test_two_names_that_are_not_files_are_refused(self):
        result = self.run_omdrop("send", str(self.file), "fred", "typo.jpg")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("typo.jpg", result.stderr)
        self.assertFalse(self.capture.exists())

    def test_two_files_of_one_name_are_refused_before_anything_is_sent(self):
        twin = self.second_file(self.file.name)

        result = self.run_omdrop("send", str(self.file), str(twin))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("photo.jpg", result.stderr)
        self.assertFalse(self.capture.exists())
        self.assertFalse(self.capture_list.exists(), "a device was asked before refusing")

    def test_a_one_file_driver_is_told_to_update_for_several(self):
        self.env["SENDER_USAGE"] = "  -n, --names  [file]"

        several = self.run_omdrop("send", str(self.file), str(self.second_file()))
        one = self.run_omdrop("send", str(self.file))

        self.assertNotEqual(several.returncode, 0)
        self.assertIn("omdrop install-driver", several.stderr)
        self.assertEqual(one.returncode, 0, one.stderr)

    def test_with_omdrop_off_a_send_without_a_name_turns_nothing_on(self):
        # In a window just opened, "the only device heard" is whichever
        # device spoke first.
        self.env["RADIO"] = "down"

        result = self.run_omdrop("send", str(self.file))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("omdrop send NAME", result.stderr)
        self.assertIn("omdrop on", result.stderr)
        self.assertFalse(self.systemctl_log.exists())
        self.assertFalse(self.capture_list.exists())
        self.assertFalse(self.capture.exists())

    def test_an_address_left_behind_by_off_is_not_an_open_window(self):
        self.env["WINDOW"] = "down"

        result = self.run_omdrop("send", str(self.file))

        self.assertIn("Omdrop is off", result.stderr)
        self.assertFalse(self.capture_list.exists())

    def test_an_open_window_is_read_from_the_helpers_json_however_it_is_spaced(self):
        self.env["WINDOW_JSON"] = '{ "visible": true, "reason": null }'

        result = self.run_omdrop("send", "--to", "6c:58", str(self.file))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("Turning it on", result.stdout)
        self.assertFalse(self.systemctl_log.exists())

    def test_a_helper_answer_that_is_not_a_json_object_is_a_closed_window(self):
        for answer in ("visible", '"visible"', '{"visible": "true"}'):
            with self.subTest(answer=answer):
                self.env["WINDOW_JSON"] = answer

                result = self.run_omdrop("send", str(self.file))

                self.assertIn("Omdrop is off", result.stderr)
                self.assertFalse(self.capture_list.exists())

    def test_a_delivered_file_is_reported_without_the_protocol_log(self):
        result = self.run_omdrop("send", str(self.file))

        self.assertIn("Sent photo.jpg (2493 B, 0.62s)", result.stdout)
        self.assertNotIn("FOUND", result.stdout)
        self.assertNotIn("INFO send", result.stdout)

    def test_a_refused_transfer_fails_and_says_so(self):
        self.env["SENDER_STDOUT"] = DECLINED
        self.env["SENDER_RC"] = "3"

        result = self.run_omdrop("send", str(self.file))

        self.assertEqual(result.returncode, 3)
        self.assertIn("declined", result.stderr)

    def unreachable_with(self, window, source):
        root = Path(self.tmp.name)
        runtime = root / "runtime"
        (runtime / "omdrop").mkdir(parents=True)
        (runtime / "omdrop" / "window").write_text(f"source={window}\n")
        (root / "config" / "omdrop").mkdir(parents=True, exist_ok=True)
        (root / "config" / "omdrop" / "settings").write_text(f"identity_source={source}\n")
        self.env.update(
            XDG_RUNTIME_DIR=str(runtime),
            SENDER_STDOUT="",
            SENDER_STDERR="e2:9d:03:6c:58:23 never opened 8770; on an iPhone, "
                          "open a share sheet or receive something to wake sharingd",
            SENDER_RC="3",
        )
        return self.run_omdrop("send", str(self.file))

    def test_an_unreachable_device_with_1password_locked_says_everyone_mode(self):
        result = self.unreachable_with("self-signed", "1password")

        self.assertEqual(result.returncode, 3)
        self.assertEqual(
            result.stderr.strip().splitlines()[-1],
            '1Password locked; using self-signed certificates. Peers must be in "Everyone" mode.',
        )
        self.assertNotIn("8770", result.stderr)

    def test_an_unreachable_device_without_1password_says_everyone_mode(self):
        result = self.unreachable_with("self-signed", "disk")

        self.assertEqual(result.returncode, 3)
        self.assertEqual(
            result.stderr.strip().splitlines()[-1],
            'Using self-signed certificates. Peers must be in "Everyone" mode.',
        )

    def test_an_unreachable_device_with_an_apple_identity_is_not_blamed_on_the_mode(self):
        result = self.unreachable_with("1password", "1password")

        self.assertEqual(result.returncode, 3)
        self.assertNotIn("Everyone", result.stderr)
        self.assertNotIn("8770", result.stderr)

    def test_cancelling_a_send_stops_the_sender_too(self):
        self.env["SENDER_SLEEP"] = "5"  # longer than the 2 s grace before SIGKILL
        proc = subprocess.Popen([OMDROP, "send", str(self.file)], env=self.env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 5
        while not self.capture.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertTrue(self.capture.exists(), "the sender never started")

        proc.terminate()
        _, err = proc.communicate(timeout=5)
        time.sleep(5.5)

        self.assertEqual(proc.returncode, 130)
        self.assertIn("Cancelled", err)
        self.assertFalse(Path(f"{self.capture}.outlived").exists(),
                         "the sender kept going after the send was cancelled")

    def test_a_running_send_is_visible_to_off_and_gone_when_it_ends(self):
        runtime = Path(self.tmp.name) / "runtime"
        runtime.mkdir()
        self.env.update(XDG_RUNTIME_DIR=str(runtime), SENDER_SLEEP="1")
        sends = runtime / "omdrop" / "sends"
        proc = subprocess.Popen([OMDROP, "send", "--to", "e2:9d", str(self.file)], env=self.env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 5
        while not self.capture.exists() and time.monotonic() < deadline:
            time.sleep(0.05)

        markers = list(sends.iterdir()) if sends.exists() else []
        self.assertEqual([m.read_text().strip() for m in markers], ["e2:9d"])

        proc.communicate(timeout=10)
        self.assertEqual(list(sends.iterdir()), [])

    def test_verbose_keeps_the_log_a_bug_report_needs(self):
        result = self.run_omdrop("send", "--verbose", str(self.file))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ASK -> accepted", result.stdout)

    def test_peers_lists_what_the_radio_can_hear(self):
        result = self.run_omdrop("peers")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.capture_list.read_text().splitlines(), ["--list"])
        self.assertIn("-47 dBm", result.stdout)

    def test_sending_without_the_driver_half_names_the_installer(self):
        self.env["OMDROP_SENDER"] = str(self.bin / "nothing-here")

        result = self.run_omdrop("send", str(self.file))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("omdrop install-driver", result.stderr)

    def test_peers_json_gives_the_panel_names_only_where_a_device_answered(self):
        self.env["PEER_LIST"] = "\n".join([
            "22:8b:38:31:89:4e   -34 dBm  [fe80::208b:38ff:fe31:894e%awdl0]:8770  hume",
            "b2:c4:98:5e:e6:be     ? dBm  [fe80::b0c4:98ff:fe5e:e6be%awdl0]:8770  (no response)",
            "f2:f2:ee:c4:5a:f7     ? dBm  [fe80::f0f2:eeff:fec4:5af7%awdl0]:8770  Brent's iPhone",
        ])

        result = self.run_omdrop("peers", "--json", "-n")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), [
            {"mac": "22:8b:38:31:89:4e", "rssi": -34, "name": "hume"},
            {"mac": "b2:c4:98:5e:e6:be", "rssi": None, "name": None},
            {"mac": "f2:f2:ee:c4:5a:f7", "rssi": None, "name": "Brent's iPhone"},
        ])

    def test_peers_json_draws_an_empty_room_as_an_empty_list(self):
        self.env["PEER_LIST"] = ""

        result = self.run_omdrop("peers", "--json")

        self.assertEqual(json.loads(result.stdout), [])


class NamedRecipientTests(SenderFixture):
    def start_on_a_clock_tick(self):
        # bash's SECONDS steps whenever the wall clock passes a whole second,
        # so a one-second OMDROP_NAME_WAIT ends at the next whole second:
        # anywhere from a moment to a second after the lookup starts. Tests
        # that time a one-second lookup start just after a whole second, so
        # the lookup has close to all of it.
        time.sleep(1 - time.time() % 1)

    def test_a_name_that_answers_on_a_later_lookup_is_found(self):
        self.env.update(
            OMDROP_NAME_WAIT="10",
            PEER_LIST=f"{ONE_PEER}  (no response)",
            PEER_LIST_LATER=f"{ONE_PEER}  Studio Mac",
        )

        result = self.run_omdrop("send", str(self.file), "Studio Mac")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Still looking", result.stdout)
        self.assertEqual(result.stdout.count("Heard from Studio Mac."), 1)
        self.assertEqual(self.sender_args()[self.sender_args().index("--mac") + 1],
                         "e2:9d:03:6c:58:23")

    def test_an_exact_name_wins_over_a_substring_match(self):
        self.env.update(
            OMDROP_NAME_WAIT="5",
            PEER_LIST=f"{THREE_PEERS.splitlines()[0]}  Studio Mac Mini",
            PEER_LIST_TAIL=f"{ONE_PEER}  Studio Mac",
            LIST_TAIL_DELAY="1",
        )

        result = self.run_omdrop("send", "studio mac", str(self.file))

        self.assertEqual(result.returncode, 0, result.stderr)
        args = self.sender_args()
        self.assertEqual(args[args.index("--mac") + 1], "e2:9d:03:6c:58:23")

    def test_duplicate_exact_names_are_refused_even_when_the_second_is_late(self):
        self.env.update(
            OMDROP_NAME_WAIT="5",
            PEER_LIST="02:00:00:00:00:01  -40 dBm  [fe80::1%awdl0]:8770  Studio Mac",
            PEER_LIST_TAIL="02:00:00:00:00:02  -50 dBm  [fe80::2%awdl0]:8770  STUDIO MAC",
            LIST_TAIL_DELAY="1",
        )

        result = self.run_omdrop("send", "studio mac", str(self.file))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("omdrop send --to 02:00:00:00:00:01", result.stderr)
        self.assertIn("omdrop send --to 02:00:00:00:00:02", result.stderr)
        self.assertFalse(self.capture.exists())

    def test_ambiguous_substrings_are_refused(self):
        self.env["PEER_LIST"] = "\n".join([
            f"{ONE_PEER}  Studio Mac",
            f"{THREE_PEERS.splitlines()[0]}  Studio Phone",
        ])

        result = self.run_omdrop("send", "studio", str(self.file))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Several devices match", result.stderr)
        self.assertFalse(self.capture.exists())

    def test_a_unique_substring_selects_the_device(self):
        self.env["PEER_LIST"] = f"{ONE_PEER}  Studio Mac"

        result = self.run_omdrop("send", "studio", str(self.file))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.capture.exists())

    def test_streaming_is_requested_only_when_supported(self):
        self.env["PEER_LIST"] = f"{ONE_PEER}  Studio Mac"
        for usage, expected in [
            ("--names [file ...]", ["--list", "--names"]),
            ("--names --stream [file ...]", ["--list", "--names", "--stream"]),
        ]:
            with self.subTest(usage=usage):
                self.env["SENDER_USAGE"] = usage
                result = self.run_omdrop("send", "Studio Mac", str(self.file))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.capture_list.read_text().splitlines(), expected)

    def test_no_match_reports_answers_and_respects_the_retry_deadline(self):
        self.env.update(OMDROP_NAME_WAIT="1", PEER_LIST=f"{ONE_PEER}  Studio Phone")
        self.start_on_a_clock_tick()
        start = time.monotonic()

        result = subprocess.run([OMDROP, "send", "Studio Mac", str(self.file)],
                                env=self.env, capture_output=True, text=True, timeout=5)

        self.assertLess(time.monotonic() - start, 2.5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Studio Phone", result.stderr)
        self.assertIn("answered in 1 seconds", result.stderr)
        self.assertFalse(self.capture.exists())

    def test_named_lookup_errors_are_not_reported_as_an_empty_room(self):
        self.env["LIST_RC"] = "4"

        result = self.run_omdrop("send", "Studio Mac", str(self.file))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("could not read the peer table", result.stderr)
        self.assertNotIn("No Apple device", result.stderr)
        self.assertFalse(self.capture.exists())

    def test_name_wait_is_decimal_and_invalid_values_use_the_default(self):
        self.env["PEER_LIST"] = f"{ONE_PEER}  Studio Mac"
        for value, seconds in [
            ("0008", 8), ("0000000000000000009", 9), ("2147483647", 2147483647),
            ("0", 120), ("000", 120), ("-1", 120), ("1+1", 120),
            ("08x", 120), ("2147483648", 120), ("99999999999999999999", 120),
        ]:
            with self.subTest(value=value):
                self.env["OMDROP_NAME_WAIT"] = value
                result = self.run_omdrop("send", "Studio Mac", str(self.file))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"(up to {seconds}s)", result.stdout)
                self.assertNotIn("value too great", result.stderr)

    def assert_lookup_is_bounded(self, **settings):
        self.env.update(OMDROP_NAME_WAIT="1", **settings)
        self.start_on_a_clock_tick()
        start = time.monotonic()
        result = subprocess.run([OMDROP, "send", "Studio Mac", str(self.file)],
                                env=self.env, capture_output=True, text=True, timeout=8)
        elapsed = time.monotonic() - start

        self.assertLess(elapsed, 4.5, "lookup or cleanup exceeded the deadline and grace")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Name lookup did not finish", result.stderr)
        self.assertFalse(self.capture.exists())
        # Check after the fake child would have completed, not immediately
        # after cancellation when even an orphan has not left its mark yet.
        time.sleep(max(0, 5.5 - elapsed))
        self.assertFalse(Path(f"{self.capture_list}.outlived").exists())
        return result

    def test_a_silent_child_with_an_open_pipe_is_stopped(self):
        self.assert_lookup_is_bounded(LIST_SLEEP="5")

    def test_a_live_child_with_closed_output_is_stopped(self):
        self.assert_lookup_is_bounded(LIST_SLEEP="5", LIST_CLOSE_OUTPUT="1")

    def test_a_hung_capability_probe_is_also_bounded(self):
        self.assert_lookup_is_bounded(HELP_SLEEP="5")

    def test_a_matching_row_followed_by_a_hang_never_selects_a_recipient(self):
        for closed_output in ("", "1"):
            with self.subTest(closed_output=bool(closed_output)):
                result = self.assert_lookup_is_bounded(
                    LIST_POST_SLEEP="5",
                    LIST_CLOSE_OUTPUT=closed_output,
                    PEER_LIST=f"{ONE_PEER}  Studio Mac",
                    PEER_LIST_TAIL=(
                        "02:00:00:00:00:02  -50 dBm  [fe80::2%awdl0]:8770  Studio Mac"
                    ),
                )
                self.assertIn("Heard from Studio Mac.", result.stdout)
                self.assertIn("nothing was sent", result.stderr)
                self.assertIn(f"  {ONE_PEER}  Studio Mac", result.stderr)

    def test_cancelling_named_discovery_stops_the_lookup(self):
        self.env.update(OMDROP_NAME_WAIT="30", LIST_SLEEP="5")
        proc = subprocess.Popen([OMDROP, "send", "Studio Mac", str(self.file)],
                                env=self.env, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        self.addCleanup(lambda: proc.poll() is None and proc.kill())
        deadline = time.monotonic() + 5
        while not self.capture_list.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertTrue(self.capture_list.exists(), "lookup never started")

        proc.terminate()
        _, err = proc.communicate(timeout=5)
        time.sleep(5.5)

        self.assertEqual(proc.returncode, 130)
        self.assertIn("Cancelled", err)
        self.assertFalse(self.capture.exists())
        self.assertFalse(Path(f"{self.capture_list}.outlived").exists())

    def test_cancelling_between_lookup_passes_is_reported(self):
        self.env.update(OMDROP_NAME_WAIT="30", PEER_LIST="")
        output = Path(self.tmp.name) / "progress"
        with output.open("w") as stream:
            proc = subprocess.Popen([OMDROP, "send", "Studio Mac", str(self.file)],
                                    env=self.env, stdout=stream,
                                    stderr=subprocess.PIPE, text=True)
            self.addCleanup(lambda: proc.poll() is None and proc.kill())
            deadline = time.monotonic() + 5
            while "Still looking" not in output.read_text() and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertIn("Still looking", output.read_text())

            proc.terminate()
            _, err = proc.communicate(timeout=5)

        self.assertEqual(proc.returncode, 130)
        self.assertIn("Cancelled", err)
        self.assertFalse(self.capture.exists())


class PeerNameTests(SenderFixture):
    """A device's name is whatever it chose to call itself. Until the sender
    cleans it, a name can carry terminal escapes, bidi overrides, or a line
    break followed by text shaped like another device's row. The command
    line cleans every name it prints or matches, and refuses a lookup in which
    one device was listed twice, since one of those rows was forged."""

    A = "02:00:00:00:00:0a  -40 dBm  [fe80::a%awdl0]:8770"
    B = "02:00:00:00:00:0b  -30 dBm  [fe80::b%awdl0]:8770"
    UNSAFE = "\x1b\x07\x7f\x85\u2028\u2029\u202a\u202e\u2066\u2069\u200b\u200f\ufeff"

    def assert_clean(self, text):
        for c in self.UNSAFE:
            self.assertNotIn(c, text, f"{ord(c):#x} printed")

    def test_a_row_forged_inside_a_name_cannot_relabel_another_device(self):
        # The attacker A calls itself "Brent's iPhone", and the line break in
        # its name forges a row that renames the real Brent's iPhone, B.
        # Before, the forged row replaced B's, and the send went to A.
        self.env.update(OMDROP_NAME_WAIT="5", PEER_LIST="\n".join([
            f"{self.B}  Brent's iPhone",
            f"{self.A}  Brent's iPhone",
            f"{self.B}  Mallory",
        ]))

        result = self.run_omdrop("send", "Brent's iPhone", str(self.file))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("listed twice in one lookup", result.stderr)
        self.assertFalse(self.capture.exists(), "sent despite a forged row")

    # Characters the cleaning removes, which kept a forged row from looking
    # like one until it was cleaned: ESC, a C1 CSI, NEL, bidi and zero-width.
    HIDING = ["\x1b", "\x9b", "\x85", "\u202e", "\u2066", "\u200b", "\ufeff", "\x07\u200f"]

    def test_a_forged_row_behind_a_removable_character_is_still_a_forged_row(self):
        # Before, the forged line failed the row pattern, was printed with
        # the character removed, and bash then read it as B's row.
        for hide in self.HIDING:
            with self.subTest(hide=repr(hide)):
                self.capture.unlink(missing_ok=True)
                self.env.update(OMDROP_NAME_WAIT="5", PEER_LIST="\n".join([
                    f"{self.B}  Brent's iPhone",
                    f"{self.A}  Brent's iPhone",
                    f"{hide}{self.B}  Mallory",
                ]))

                result = self.run_omdrop("send", "Brent's iPhone", str(self.file))

                self.assertNotEqual(result.returncode, 0)
                self.assertIn("listed twice in one lookup", result.stderr)
                self.assertFalse(self.capture.exists(), "sent despite a forged row")

    def test_a_line_that_is_not_a_row_never_reads_as_one(self):
        # Whatever is left of a line that is not a row is printed so that
        # nothing reading the listing afterwards can take it for one.
        self.env["PEER_LIST"] = f"{self.A}  x\nnot a row {self.B}  -30 dBm  [fe80::b%awdl0]:8770"

        result = self.run_omdrop("peers", "-n")

        self.assertEqual(result.returncode, 0, result.stderr)
        for line in result.stdout.splitlines()[1:]:
            self.assertTrue(line.startswith("  "), line)

    def test_the_panels_stream_stops_at_a_forged_row(self):
        self.env["PEER_LIST"] = "\n".join([
            f"{self.B}  Brent's iPhone",
            f"{self.A}  x",
            f"{self.B}  Mallory",
        ])

        result = self.run_omdrop("peers", "--json", "-n", "--stream")

        names = [json.loads(line)["name"] for line in result.stdout.splitlines()]
        self.assertEqual(names, ["Brent's iPhone", "x"])

    def test_the_json_listing_refuses_a_forged_row(self):
        self.env["PEER_LIST"] = f"{self.B}  Brent's iPhone\n{self.B}  Mallory"

        result = self.run_omdrop("peers", "--json", "-n")

        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("Mallory", result.stdout)
        self.assertIn("listed twice in one lookup", result.stderr)

    def test_a_carriage_return_does_not_end_a_row(self):
        # bash reads rows up to \n; Python's text mode also ended them at \r,
        # so the panel saw a row the command line never did.
        self.env["PEER_LIST"] = f"{self.A}  Mallory\r{self.B}  Brent's iPhone"

        result = self.run_omdrop("peers", "--json", "-n")

        self.assertEqual(result.returncode, 0, result.stderr)
        peers = json.loads(result.stdout)
        self.assertEqual([p["mac"] for p in peers], ["02:00:00:00:00:0a"])
        self.assertNotIn("\r", peers[0]["name"])

    def test_names_are_printed_without_control_or_invisible_characters(self):
        self.env["PEER_LIST"] = f"{self.A}  Studio{self.UNSAFE} Mac \t"

        result = self.run_omdrop("peers", "-n")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, f"{self.A}  Studio Mac\n")

        result = self.run_omdrop("peers", "--json", "-n")
        self.assertEqual(json.loads(result.stdout)[0]["name"], "Studio Mac")

    def test_a_name_is_cut_to_255_bytes_on_a_character_boundary(self):
        self.env["PEER_LIST"] = f"{self.A}  {'é' * 200}"

        result = self.run_omdrop("peers", "--json", "-n")

        self.assertEqual(json.loads(result.stdout)[0]["name"], "é" * 127)

    def test_a_name_of_only_unsafe_characters_is_no_name(self):
        self.env["PEER_LIST"] = f"{self.A}  {self.UNSAFE}"

        result = self.run_omdrop("peers", "--json", "-n")

        self.assertEqual(json.loads(result.stdout)[0]["name"], None)

    def test_heard_from_and_several_devices_print_clean_names(self):
        self.env.update(OMDROP_NAME_WAIT="5", PEER_LIST="\n".join([
            f"{self.A}  Studio\x1b[31m Mac{self.UNSAFE}",
            f"{self.B}  Studio\u202e Phone",
        ]))

        result = self.run_omdrop("send", "studio", str(self.file))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Heard from Studio[31m Mac.", result.stdout)
        self.assertIn("Heard from Studio Phone.", result.stdout)
        self.assertIn("Several devices match", result.stderr)
        self.assert_clean(result.stdout + result.stderr)
        self.assertFalse(self.capture.exists())


class SendPickTests(SenderFixture):
    """`send --pick`: where the chooser opens, and what it remembers."""

    def setUp(self):
        super().setUp()
        root = Path(self.tmp.name)
        self.downloads = root / "Downloads"
        self.downloads.mkdir()
        (root / "config" / "airdrop" / "config.toml").write_text(
            f'name = "Study Mac"\ndownload_dir = "{self.downloads}"\n')
        self.opened_at = root / "opened-at"
        # Stands in for the chooser: notes where it was asked to open, and
        # answers with PICK_ANSWER, or cancels when that is empty.
        picker = self.command("picker", """#!/bin/sh
printf '%s\\n' "$2" > "$OPENED_AT"
[ -n "$PICK_ANSWER" ] || exit 1
# One path per line here, NUL-terminated there, as pick.py answers.
printf '%s\\n' "$PICK_ANSWER" | tr '\\n' '\\0'
[ -z "$PICK_ANSWER_2" ] || printf '%s\\0' "$PICK_ANSWER_2"
""")
        self.env.update(OMDROP_PICKER=str(picker), OPENED_AT=str(self.opened_at))

    def pick_and_send(self, answer):
        self.env["PICK_ANSWER"] = str(answer)
        return self.run_omdrop("send", "--pick", "--to", "6c:58")

    def test_the_chooser_opens_where_the_last_file_was_sent_from(self):
        photos = Path(self.tmp.name) / "Photos"
        photos.mkdir()
        (photos / "cat.jpg").write_bytes(b"x")

        first = self.pick_and_send(photos / "cat.jpg")
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(self.opened_at.read_text().strip(), str(self.downloads))
        self.assertEqual(self.capture.read_text().splitlines()[-1], str(photos / "cat.jpg"))

        self.pick_and_send(photos / "cat.jpg")
        self.assertEqual(self.opened_at.read_text().strip(), str(photos))

        # A remembered folder that has gone is forgotten, not opened.
        (photos / "cat.jpg").unlink()
        photos.rmdir()
        self.pick_and_send(self.file)
        self.assertEqual(self.opened_at.read_text().strip(), str(self.downloads))

    def test_every_chosen_file_is_sent_together(self):
        # A newline in a name is what the NUL separator is for.
        odd = Path(self.tmp.name) / "two\nlines.txt"
        odd.write_text("x")
        self.env["PICK_ANSWER"] = str(self.file)
        self.env["PICK_ANSWER_2"] = str(odd)

        result = self.run_omdrop("send", "--pick", "--to", "6c:58")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Preparing 2 files...", result.stdout)
        args = self.capture.read_text().split("\n--\n", 1)[1]
        self.assertEqual(args, f"{self.file}\n{odd}\n")

    def test_a_cancelled_chooser_sends_nothing_and_says_nothing(self):
        self.env["PICK_ANSWER"] = ""

        result = self.run_omdrop("send", "--pick", "--to", "6c:58")

        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, "")
        self.assertFalse(self.capture.exists())


class SoundSettingTests(SenderFixture):
    def test_muting_the_radar_is_remembered(self):
        self.run_omdrop("sound", "off")

        self.assertEqual(self.run_omdrop("sound").stdout.strip(), "off")


if __name__ == "__main__":
    unittest.main()
