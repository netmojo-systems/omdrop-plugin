import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OMDROP = ROOT / "bin" / "omdrop"

def apple_wifi_sysfs(root):
    """A sysfs tree holding one Broadcom (0x14e4) network controller on an
    Apple Silicon device tree, which is what install-driver checks for before
    doing anything. These tests are about the script it writes, not the
    machine they run on."""
    dev = Path(root) / "sys" / "bus" / "pci" / "devices" / "0000:01:00.0"
    dev.mkdir(parents=True)
    (dev / "vendor").write_text("0x14e4\n")
    (dev / "class").write_text("0x028000\n")
    dt = Path(root) / "sys" / "firmware" / "devicetree" / "base"
    dt.mkdir(parents=True)
    (dt / "compatible").write_bytes(b"apple,j293\0apple,t8103\0apple,arm-platform\0")
    return str(Path(root) / "sys")


class FirewallCommandTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
