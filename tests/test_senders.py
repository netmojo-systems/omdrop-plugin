"""`omdrop senders remove` has to revoke what the receiver matches."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OMDROP = ROOT / "bin" / "omdrop"
sys.path.insert(0, str(ROOT / "bin"))

import contacts  # noqa: E402


class SendersTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.env = os.environ.copy()
        self.env.update(XDG_CONFIG_HOME=tmp.name, OMDROP_IMPLEMENTATION="python",
                        OMDROP_DISCOVERABLE="/nonexistent")
        self.file = Path(tmp.name) / "omdrop" / "known-senders"

    def senders(self, *args):
        r = subprocess.run([OMDROP, "senders", *args], env=self.env,
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_removing_the_only_sender_revokes_it(self):
        self.senders("add", "a@b.co")
        self.senders("remove", "a@b.co")
        self.assertEqual("", self.file.read_text())
        self.assertEqual(set(), contacts.known_hashes(self.file))

    def test_removing_every_sender_in_turn_empties_the_list(self):
        self.senders("add", "a@b.co", "c@d.co")
        self.senders("remove", "a@b.co")
        self.senders("remove", "c@d.co")
        self.assertEqual("", self.file.read_text())

    def test_removal_matches_the_identity_the_receiver_hashes(self):
        self.file.parent.mkdir()
        self.file.write_text("\u00a0+1 (604) 555-0100\u00a0\n# Friend@Example.com\n"
                             "Friend@Example.com\r\nc@d.co")
        self.senders("add", "16045550100", "friend@example.com")
        self.assertEqual(4, len(self.file.read_text().splitlines()))
        self.senders("remove", "+1 (604) 555-0100", "friend@example.com")
        self.assertEqual("# Friend@Example.com\nc@d.co\n", self.file.read_text())
        self.assertEqual({contacts.hash_identifier("c@d.co")},
                         contacts.known_hashes(self.file))


if __name__ == "__main__":
    unittest.main()
