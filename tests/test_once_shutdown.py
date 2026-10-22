"""A one-file window has to actually close after its one file.

2026-09-17, twice: the watcher announced the file it had stored and stopped,
and the receiver stayed listening -- so the next sender got in too. `off`
calls `cancel_window`, which stops `omdrop-watch.service`; the watcher was
running INSIDE that service, so systemd killed its cgroup partway through the
shutdown it had just started. The close has to outlive the watcher.
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OMDROP = ROOT / "bin" / "omdrop"


# The receiver's own record prefix: `%(asctime)s %(levelname)s %(name)s: `.
TS = "2026-10-10 16:14:20,098 INFO root: "


class OneFileShutdownTests(unittest.TestCase):
    def run_watch(self, once=True, systemd_run=True, journal=None):
        """`omdrop watch` over a stubbed journal. `journal` makes the log from
        (root, downloads); by default the receiver's record of one file."""
        source = OMDROP.read_text()
        start = source.index("cmd_watch() {")
        fragment = source[start:source.index("\n# The URL inside", start)]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            downloads = root / "Downloads"
            downloads.mkdir()
            (downloads / "arrived.jpg").write_text("x")
            capture = root / "events"
            log = root / "journal"
            log.write_text(journal(root, downloads) if journal
                           else f"{TS}upload ABC: stored arrived.jpg\n")
            # Outside the f-string: a backslash in its expressions needs Python 3.12.
            systemd_run_body = ("printf 'systemd-run %s\\n' \"$*\" >> \"$CAPTURE\""
                                if systemd_run else "return 1")
            harness = f"""
set -uo pipefail
SELF={root}/omdrop
UNIT=airdrop-receiver.service
CAPTURE={capture}
effective_dir(){{ printf '%s' {str(downloads)!r}; }}
journalctl(){{ cat {str(log)!r}; }}
systemd-run(){{ {systemd_run_body}; }}
{fragment}
cmd_watch {"--once" if once else ""}
"""
            # $SELF is invoked directly for `handle`, and must be a real file.
            self_stub = root / "omdrop"
            # `handle` takes a moment, so a close that does not wait for it
            # is logged first.
            self_stub.write_text(
                '#!/bin/sh\n[ "$1" = handle ] && sleep 1\n'
                'printf \'self %s\\n\' "$*" >> "$CAPTURE"\n')
            self_stub.chmod(0o755)
            env = os.environ.copy()
            env["CAPTURE"] = str(capture)
            result = subprocess.run(["bash", "-c", harness], env=env,
                                    capture_output=True, text=True)
            events = capture.read_text() if capture.exists() else ""
            return result, events

    def test_without_systemd_run_the_close_waits_for_the_notification(self):
        # handle then runs inside the watcher, and the close would kill it.
        result, events = self.run_watch(once=True, systemd_run=False)
        lines = events.splitlines()
        handled = [n for n, l in enumerate(lines) if l.startswith("self handle")]
        closed = [n for n, l in enumerate(lines) if l.startswith("self off")]
        self.assertTrue(handled and closed, result.stdout + result.stderr + events)
        self.assertLess(handled[0], closed[0], events)

    def test_the_close_outlives_the_watcher_that_asked_for_it(self):
        # The regression: `off` ran as a child of the unit `off` stops, so it
        # died with it and the receiver was never stopped.
        result, events = self.run_watch(once=True)
        self.assertIn("off", events, result.stdout + result.stderr)
        self.assertRegex(events, r"systemd-run .*\boff\b")

    def test_the_notification_outlives_the_watcher_too(self):
        # `handle` decodes a HEIC preview before it notifies. Inside the
        # watcher's cgroup, the close that follows a one-file window killed
        # it, and the photo arrived with no notification at all.
        result, events = self.run_watch(once=True)
        self.assertRegex(events, r"systemd-run .*\bhandle\b .*arrived\.jpg",
                         result.stdout + result.stderr)
        self.assertNotIn("self handle", events)

    def test_an_ordinary_window_is_not_closed_by_an_arrival(self):
        _, events = self.run_watch(once=False)
        self.assertNotIn("off", events)

    def test_the_notification_unit_has_a_memory_ceiling(self):
        # handle decodes a sender's HEIC for its preview, and in Everyone mode
        # anyone nearby chooses that file.
        result, events = self.run_watch(once=False)
        self.assertRegex(events, r"systemd-run .*-p MemoryMax=512M .*\bhandle\b",
                         result.stdout + result.stderr)

    def test_a_forged_record_naming_a_file_outside_the_download_folder_is_ignored(self):
        # A sender's text reaches the receiver's log. Neither a line without
        # the receiver's own prefix, nor one where a record's words appear
        # later in another message, nor a name that is not a file directly in
        # the folder, is an arrival: nothing is announced, and a one-file
        # window stays open.
        def journal(root, downloads):
            secret = root / "secret.png"
            secret.write_text("x")
            (downloads / "unrelated.jpg").write_text("x")
            (downloads / "link.png").symlink_to(secret)
            return "".join(line + "\n" for line in (
                f"upload X: stored {secret}",
                f"{TS}upload X: stored {secret}",
                f"{TS}GET from Mac upload X: stored unrelated.jpg",
                f"{TS}upload X: stored ../secret.png",
                f"{TS}upload X: stored link.png",
                f"{TS}link stored as ../secret.png -> https://e.x/",
            ))
        result, events = self.run_watch(once=True, journal=journal)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("announcing", result.stdout, events)
        self.assertNotIn("off", events)
        self.assertNotIn("secret.png", events)
        self.assertNotIn("handle", events)


if __name__ == "__main__":
    unittest.main()
