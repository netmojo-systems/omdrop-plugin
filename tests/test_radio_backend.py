"""A radio backend other than omdrop-awdl can describe itself.

omdrop's radio half is a separate package. Its helper may answer
`omdrop-discoverable probe --json` (docs/radio-backend.md); when it does, the
hardware and install checks are the backend's, so a machine without Apple's
Broadcom Wi-Fi is not refused out of hand. A helper that does not answer gets
the Broadcom checks exactly as before.
"""
import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OMDROP = ROOT / "bin" / "omdrop"

BROADCOM_SAYS = "no Apple Broadcom Wi-Fi"


def helper(probe):
    """An omdrop-discoverable that answers probe with PROBE (a dict), or, given
    None, behaves like omdrop-awdl's: usage and exit 2 for a subcommand it does
    not know."""
    if probe is None:
        return '#!/bin/sh\necho "usage: omdrop-discoverable start|stop|status" >&2\nexit 2\n'
    return ("#!/bin/sh\n"
            "[ \"$1\" = probe ] || exit 2\n"
            f"cat <<'EOF'\n{json.dumps(probe)}\nEOF\n")


class RadioBackendTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        tmp = Path(self.tmp.name)
        self.bin = tmp / "bin"
        self.bin.mkdir()
        # The receiver's service is installed (`systemctl --user cat` finds it),
        # so doctor's only findings are the radio's and the receiver
        # library's; nothing is active, ufw included.
        self.command("systemctl", '#!/bin/sh\ncase "$*" in *is-active*) exit 3 ;; esac\nexit 0\n')
        self.command("omarchy-launch-floating-terminal-with-presentation",
                     "#!/bin/sh\nprintf '%s\\n' \"$1\"\n")
        # A machine with no PCI network hardware at all: not a Mac.
        (tmp / "sys" / "bus" / "pci" / "devices").mkdir(parents=True)
        self.env = os.environ.copy()
        self.env.update(PATH=f"{self.bin}:{self.env['PATH']}",
                        HOME=str(tmp),
                        XDG_CONFIG_HOME=str(tmp / ".config"),
                        OMDROP_SYSFS=str(tmp / "sys"),
                        OMDROP_DISCOVERABLE=str(self.bin / "omdrop-discoverable"))

    def command(self, name, body):
        path = self.bin / name
        path.write_text(body)
        path.chmod(0o755)

    def omdrop(self, *args):
        return subprocess.run([OMDROP, *args], env=self.env, capture_output=True, text=True)

    def doctor(self):
        result = self.omdrop("doctor", "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def without_receiver_library(self):
        # A libarchive without the API the receiver calls, ahead of the real
        # one, is what "not installed" looks like to receiver_libs_installed.
        fake = Path(self.tmp.name) / "py" / "libarchive"
        fake.mkdir(parents=True)
        (fake / "__init__.py").write_text("")
        self.env["PYTHONPATH"] = str(fake.parent)

    def test_a_probing_backend_owns_the_hardware_check(self):
        self.command("omdrop-discoverable", helper({
            "backend": "owl", "version": "0.1.0", "hardware": True, "contract": "0.7.0",
            "missing": [{"id": "radio", "say": "Wi-Fi is not connected."}]}))
        missing = self.doctor()["missing"]
        self.assertEqual(missing[0], {"id": "radio", "say": "Wi-Fi is not connected."})
        self.assertNotIn(BROADCOM_SAYS, json.dumps(missing))

    def test_a_ready_backend_leaves_only_the_plugins_own_findings(self):
        self.command("omdrop-discoverable", helper({
            "backend": "owl", "version": "0.1.0", "hardware": True, "contract": "0.7.0",
            "missing": []}))
        ids = {m["id"] for m in self.doctor()["missing"]}
        self.assertTrue(ids <= {"library"}, ids)

    def test_hardware_the_backend_cannot_drive_is_reported_alone(self):
        self.command("omdrop-discoverable", helper({
            "backend": "owl", "version": "0.1.0", "hardware": False,
            "missing": [{"id": "hardware", "say": "No supported Wi-Fi card."},
                        {"id": "radio", "say": "never shown"}]}))
        self.without_receiver_library()
        self.assertEqual(self.doctor()["missing"],
                         [{"id": "hardware", "say": "No supported Wi-Fi card."}])

    def test_a_helper_without_probe_gets_the_broadcom_checks(self):
        self.command("omdrop-discoverable", helper(None))
        missing = self.doctor()["missing"]
        self.assertEqual([m["id"] for m in missing], ["hardware"])
        self.assertIn(BROADCOM_SAYS, missing[0]["say"])

    def intel_mac(self, device):
        # Broadcom Wi-Fi on PCI, but no Apple Silicon device tree: an Intel
        # MacBook, where omdrop-awdl's package does not even build.
        dev = Path(self.tmp.name) / "sys" / "bus" / "pci" / "devices" / "0000:03:00.0"
        dev.mkdir(exist_ok=True)
        (dev / "vendor").write_text("0x14e4\n")
        (dev / "device").write_text(device + "\n")
        (dev / "class").write_text("0x028000\n")

    def test_an_intel_mac_is_pointed_at_the_backend_for_its_chip(self):
        self.command("omdrop-discoverable", helper(None))
        for device, backend in (("0x43a0", "omdrop-bcm4360"), ("0x43ba", "omdrop-owl")):
            with self.subTest(device=device):
                self.intel_mac(device)
                missing = self.doctor()["missing"]
                self.assertEqual([m["id"] for m in missing], ["hardware"])
                self.assertIn(backend, missing[0]["say"])
                self.assertIn("Apple Silicon", missing[0]["say"])

    def test_install_on_an_intel_mac_builds_nothing(self):
        self.command("omdrop-discoverable", helper(None))
        self.intel_mac("0x43ba")
        result = self.omdrop("install-driver")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("omdrop-owl", result.stderr)
        for broadcom in ("brcmfmac-awdl-dkms", "makepkg", "omdrop-awdl"):
            self.assertNotIn(broadcom, result.stdout)

    def test_install_with_a_probing_backend_never_builds_the_broadcom_driver(self):
        self.command("omdrop-discoverable", helper({
            "backend": "owl", "version": "0.1.0", "hardware": True, "missing": []}))
        self.command("pacman", "#!/bin/sh\nexit 1\n")
        self.without_receiver_library()
        result = self.omdrop("install-driver")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("pacman -S --needed --asdeps python-libarchive-c keyutils", result.stdout)
        for broadcom in ("brcmfmac-awdl-dkms", "makepkg", "omdrop-awdl"):
            self.assertNotIn(broadcom, result.stdout)

    def test_install_with_a_probing_backend_and_nothing_missing_does_nothing(self):
        self.command("omdrop-discoverable", helper({
            "backend": "owl", "version": "0.1.0", "hardware": True, "missing": []}))
        result = self.omdrop("install-driver")
        if "Opening a terminal" in result.stdout:
            self.skipTest("this machine lacks the receiver's packages; covered above")
        self.assertIn("Nothing to do", result.stdout)
        self.assertIn("owl 0.1.0", result.stdout)


    def test_a_probe_that_hangs_is_the_backends_problem_not_a_missing_mac(self):
        # The child sleep keeps stdout open after the shell is killed, which
        # is what a hung helper usually looks like.
        self.command("omdrop-discoverable",
                     '#!/bin/sh\n[ "$1" = probe ] || exit 2\nsleep 30\necho "{}"\n')
        self.env["OMDROP_PROBE_TIMEOUT"] = "1"
        start = time.monotonic()
        missing = self.doctor()["missing"]
        self.assertLess(time.monotonic() - start, 10)
        self.assertEqual(missing[0]["id"], "backend")
        self.assertIn("did not answer", missing[0]["say"])
        self.assertNotIn(BROADCOM_SAYS, json.dumps(missing))

    def test_a_probe_that_hangs_offers_no_install_button(self):
        # install-driver refuses for a backend that does not answer, so the
        # library item, which brings up the panel's button, stays out.
        self.command("omdrop-discoverable",
                     '#!/bin/sh\n[ "$1" = probe ] || exit 2\nsleep 30\n')
        self.env["OMDROP_PROBE_TIMEOUT"] = "1"
        self.without_receiver_library()
        self.assertEqual([m["id"] for m in self.doctor()["missing"]], ["backend"])

    def test_install_refuses_when_the_probe_hangs(self):
        self.command("omdrop-discoverable",
                     '#!/bin/sh\n[ "$1" = probe ] || exit 2\nsleep 30\n')
        self.env["OMDROP_PROBE_TIMEOUT"] = "1"
        result = self.omdrop("install-driver")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not answer", result.stderr)
        for broadcom in ("brcmfmac-awdl-dkms", "makepkg", "omdrop-awdl"):
            self.assertNotIn(broadcom, result.stdout)

    def test_an_answer_without_a_backend_name_is_not_a_probe(self):
        self.command("omdrop-discoverable", helper({"visible": True}))
        self.assertIn(BROADCOM_SAYS, self.doctor()["missing"][0]["say"])

    def test_a_backend_below_the_minimum_contract_is_a_blocker_that_names_it(self):
        for contract in ("0.1.0", None):
            with self.subTest(contract=contract):
                probe = {"backend": "owl", "version": "0.1.0", "hardware": True, "missing": []}
                if contract:
                    probe["contract"] = contract
                self.command("omdrop-discoverable", helper(probe))
                first = self.doctor()["missing"][0]
                self.assertEqual(first["id"], "backend")
                self.assertIn("owl", first["say"])
                self.assertIn(contract or "none", first["say"])

    def test_a_backend_cannot_claim_the_ids_the_panel_acts_on(self):
        self.command("omdrop-discoverable", helper({
            "backend": "owl", "version": "0.1.0", "hardware": True, "contract": "0.8.1",
            "missing": [{"id": "driver", "say": "The OWL daemon is missing."},
                        {"id": "radio", "say": "Wi-Fi is not connected."}]}))
        ids = [m["id"] for m in self.doctor()["missing"]]
        self.assertEqual(ids[:2], ["backend-driver", "radio"])
        self.assertNotIn("driver", ids)

    def test_a_missing_sender_names_the_backend_not_install_driver(self):
        self.command("omdrop-discoverable", helper({
            "backend": "owl", "version": "0.1.0", "hardware": True, "contract": "0.8.1",
            "missing": []}))
        self.env["OMDROP_SENDER"] = str(self.bin / "nothing-here")
        photo = Path(self.tmp.name) / "photo.jpg"
        photo.write_bytes(b"x")
        result = self.omdrop("send", str(photo))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("(owl)", result.stderr)
        self.assertNotIn("Update it with: omdrop install-driver", result.stderr)


if __name__ == "__main__":
    unittest.main()
