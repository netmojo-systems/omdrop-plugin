import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OMDROP = ROOT / "bin" / "omdrop"

def apple_wifi_sysfs(root):
    """A sysfs tree holding one Broadcom (0x14e4) network controller, which is
    what install-driver checks for before doing anything. These tests are about
    the script it writes, not the machine they run on."""
    dev = Path(root) / "sys" / "bus" / "pci" / "devices" / "0000:01:00.0"
    dev.mkdir(parents=True)
    (dev / "vendor").write_text("0x14e4\n")
    (dev / "class").write_text("0x028000\n")
    return str(Path(root) / "sys")


class UfwFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.bin = Path(self.tmp.name) / "bin"
        self.bin.mkdir()
        self.capture = Path(self.tmp.name) / "capture"
        self.env = os.environ.copy()
        self.env.update(
            PATH=f"{self.bin}:{self.env['PATH']}",
            CAPTURE=str(self.capture),
            OMDROP_DISCOVERABLE="/bin/sh",
            OMDROP_SYSFS=apple_wifi_sysfs(self.tmp.name),
        )
        # UFW's own files are this test's, not the machine's: enforcing,
        # dropping incoming traffic by default, and no rules file, so whether
        # the rule is there can't be told until a test writes one.
        etc = Path(self.tmp.name) / "etc"
        self.ufw = etc / "ufw"
        self.ufw.mkdir(parents=True)
        (etc / "default").mkdir()
        self.policy = etc / "default" / "ufw"
        self.policy.write_text('IPV6=yes\nDEFAULT_INPUT_POLICY="DROP"\n')
        (self.ufw / "ufw.conf").write_text("ENABLED=yes\nLOGLEVEL=low\n")
        self.env["OMDROP_UFW_ETC"] = str(etc)
        self.command(
            "systemctl",
            """#!/bin/sh
[ "$1" = is-active ] && exit "${SYSTEMCTL_RC:-0}"
exit 0
""",
        )
        self.command(
            "sudo",
            """#!/bin/sh
: > "$CAPTURE"
for arg do printf '<%s>\\n' "$arg" >> "$CAPTURE"; done
""",
        )
        self.command("ufw", "#!/bin/sh\nexit 0\n")

    def command(self, name, body):
        path = self.bin / name
        path.write_text(body)
        path.chmod(0o755)

    def run_omdrop(self, *args):
        return subprocess.run(
            [OMDROP, *args], env=self.env, capture_output=True, text=True
        )

    def captured_args(self):
        return self.capture.read_text().splitlines()


class FirewallCommandTests(UfwFixture):
    def test_install_opens_only_receiver_port_on_awdl_link_local_ipv6(self):
        result = self.run_omdrop("firewall", "install")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.captured_args(),
            [
                "<ufw>",
                "<allow>",
                "<in>",
                "<on>",
                "<awdl0>",
                "<from>",
                "<fe80::/10>",
                "<to>",
                "<fe80::/10>",
                "<port>",
                "<8771>",
                "<proto>",
                "<tcp>",
                "<comment>",
                "<Omdrop AirDrop receiver>",
            ],
        )

    def test_install_does_not_enable_or_change_inactive_ufw(self):
        self.env["SYSTEMCTL_RC"] = "3"

        result = self.run_omdrop("firewall", "install")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.capture.exists())
        self.assertIn("not active", result.stdout)

    def test_remove_deletes_the_same_narrow_rule(self):
        result = self.run_omdrop("firewall", "remove")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.captured_args()[:4], ["<ufw>", "<--force>", "<delete>", "<allow>"])
        self.assertEqual(self.captured_args()[4:], [
            "<in>", "<on>", "<awdl0>", "<from>", "<fe80::/10>",
            "<to>", "<fe80::/10>", "<port>", "<8771>", "<proto>", "<tcp>",
            "<comment>", "<Omdrop AirDrop receiver>",
        ])

    def test_dependency_installer_runs_firewall_setup_in_the_same_terminal(self):
        self.command("python3", "#!/bin/sh\nexit 1\n")
        self.env["OMDROP_RECEIVER_PYTHON"] = str(self.bin / "python3")
        self.command(
            "omarchy-launch-floating-terminal-with-presentation",
            """#!/bin/sh
printf '%s' "$1" > "$CAPTURE"
""",
        )

        result = self.run_omdrop("install-driver")

        self.assertEqual(result.returncode, 0, result.stderr)
        command = self.capture.read_text()
        # Last, so sudo is authenticated by the package work ahead of it
        # rather than prompting a second time.
        self.assertIn("firewall install", command)
        self.assertLess(command.index("sudo pacman"), command.index("firewall install"))


# The receiver's rule as `ufw` writes it into user6.rules, comment and all.
RECEIVER_TUPLE = ("### tuple ### allow tcp 8771 fe80::/10 any fe80::/10 in_awdl0 "
                  "comment=4f6d64726f702041697244726f70207265636569766572")
SSH_TUPLE = "### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in"


class FirewallReadinessTests(UfwFixture):
    """UFW enforcing without the receiver's rule drops every sender while the
    radio advertises. doctor says so when that is certain, and install-driver
    adds the rule unless it is known to be there."""

    def setUp(self):
        super().setUp()
        # A radio backend with nothing missing, so the plugin's own items are
        # all there is.
        probe = {"backend": "owl", "version": "0.1.0", "hardware": True,
                 "contract": "0.8.1", "missing": []}
        self.command("omdrop-discoverable",
                     "#!/bin/sh\n[ \"$1\" = probe ] || exit 2\n"
                     f"cat <<'EOF'\n{json.dumps(probe)}\nEOF\n")
        self.env["OMDROP_DISCOVERABLE"] = str(self.bin / "omdrop-discoverable")
        self.command("omarchy-launch-floating-terminal-with-presentation",
                     "#!/bin/sh\nprintf '%s\\n' \"$1\"\n")

    def rules(self, *tuples):
        (self.ufw / "user6.rules").write_text(
            "*filter\n" + "".join(f"{t}\n" for t in tuples) + "COMMIT\n")

    def ids(self):
        result = self.run_omdrop("doctor", "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        return [m["id"] for m in json.loads(result.stdout)["missing"]]

    def test_rules_without_the_receivers_are_reported_last(self):
        self.rules(SSH_TUPLE)
        result = self.run_omdrop("doctor", "--json")
        missing = json.loads(result.stdout)["missing"]
        self.assertEqual(missing[-1]["id"], "firewall")
        self.assertIn("Apple devices can find this computer but not connect",
                      missing[-1]["say"])

    def test_nothing_is_reported_unless_ufw_certainly_drops_the_receiver(self):
        cases = {
            "the rule is there": lambda: self.rules(SSH_TUPLE, RECEIVER_TUPLE),
            "the rules can't be read": lambda: None,
            "the default policy can't be read": lambda: (
                self.rules(SSH_TUPLE), self.policy.unlink()),
            "incoming traffic is accepted by default": lambda: (
                self.rules(SSH_TUPLE),
                self.policy.write_text('DEFAULT_INPUT_POLICY="ACCEPT"\n')),
            "ufw is disabled": lambda: (
                self.rules(SSH_TUPLE),
                (self.ufw / "ufw.conf").write_text("ENABLED=no\n")),
            "ufw.service is inactive": lambda: (
                self.rules(SSH_TUPLE), self.env.update(SYSTEMCTL_RC="3")),
        }
        for name, arrange in cases.items():
            with self.subTest(name):
                (self.ufw / "user6.rules").unlink(missing_ok=True)
                (self.ufw / "ufw.conf").write_text("ENABLED=yes\n")
                self.policy.write_text('DEFAULT_INPUT_POLICY="DROP"\n')
                self.env.pop("SYSTEMCTL_RC", None)
                arrange()
                self.assertNotIn("firewall", self.ids())

    def test_a_broader_rule_that_admits_the_receiver_is_enough(self):
        for broader in ("### tuple ### allow tcp 8771 ::/0 any ::/0 in",
                        "### tuple ### allow any any ::/0 any ::/0 in_awdl0",
                        "### tuple ### allow tcp 8000:9000 ::/0 any ::/0 in",
                        "### tuple ### allow tcp 80,443,8771 ::/0 any ::/0 in",
                        "### tuple ### limit tcp 8771 ::/0 any ::/0 in",
                        "### tuple ### allow_log tcp 8771 ::/0 any ::/0 in"):
            with self.subTest(broader):
                self.rules(SSH_TUPLE, broader)
                self.assertNotIn("firewall", self.ids())

    def test_a_rule_that_cant_admit_the_receiver_doesnt_count(self):
        for other in (RECEIVER_TUPLE.replace(" 8771 ", " 87710 "),
                      RECEIVER_TUPLE.replace(" 8771 ", " 8772:9000 "),
                      RECEIVER_TUPLE.replace("in_awdl0", "in_awdl01"),
                      RECEIVER_TUPLE.replace("in_awdl0", "out_awdl0"),
                      RECEIVER_TUPLE.replace(" tcp ", " udp "),
                      RECEIVER_TUPLE.replace("allow", "deny")):
            with self.subTest(other):
                self.rules(other)
                self.assertIn("firewall", self.ids())

    def test_install_adds_the_rule_unless_it_is_known_to_be_there(self):
        for rules, adds in (((SSH_TUPLE,), True), (None, True),
                            ((SSH_TUPLE, RECEIVER_TUPLE), False)):
            with self.subTest(rules=rules):
                (self.ufw / "user6.rules").unlink(missing_ok=True)
                if rules:
                    self.rules(*rules)
                result = self.run_omdrop("install-driver")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual("firewall install" in result.stdout, adds, result.stdout)

    def test_a_current_mac_with_the_rule_has_nothing_to_do(self):
        # omdrop-awdl's helper, which doesn't answer probe, and its package
        # at the pinned version.
        self.command("omdrop-discoverable",
                     "#!/bin/sh\necho 'usage: omdrop-discoverable start|stop|status' >&2\nexit 2\n")
        self.command("pacman", "#!/bin/sh\n[ \"$1\" = -Q ] && echo 'brcmfmac-awdl-dkms 0.10.0-1'\n")
        self.rules(SSH_TUPLE, RECEIVER_TUPLE)
        result = self.run_omdrop("install-driver")
        if "pacman -S" in result.stdout:
            self.skipTest("this machine lacks the receiver's packages")
        self.assertIn("Nothing to do", result.stdout)
        self.rules(SSH_TUPLE)
        result = self.run_omdrop("install-driver")
        self.assertTrue(result.stdout.startswith(
            "Opening a terminal to add the firewall rule the receiver needs.\n"), result.stdout)
        self.assertIn("firewall install", result.stdout)
        self.assertNotIn("makepkg", result.stdout)


if __name__ == "__main__":
    unittest.main()
