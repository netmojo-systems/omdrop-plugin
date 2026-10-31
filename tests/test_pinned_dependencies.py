"""Everything this plugin installs has to be pinned to an exact revision.

The marketplace's security baseline refuses an unpinned remote build, and its
reviewer refused the listing a second time for a subtler version of the same
thing: `opendrop` was installed by package NAME through an AUR helper, so the
code the receiver imports and executes could change after the reviewed commit.
A name is not a revision. These tests read the install script the plugin would
run and insist every source it builds is named by a full commit SHA, and that
anything else comes from the official repositories through pacman.
"""

import os
import re
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


class PinnedDependencyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.bin = Path(self.tmp.name) / "bin"
        self.bin.mkdir()
        # Nothing is installed and no repository carries the driver, which is
        # the state that makes the plugin emit its full build script. The
        # launcher is stubbed rather than removed: it is what the real run
        # hands the script to, so echoing its argument captures exactly the
        # commands a user's terminal would execute.
        self.command("python3", "#!/bin/sh\nexit 1\n")       # receiver library missing
        self.command("pacman", "#!/bin/sh\nexit 1\n")        # no repo package
        self.command("systemctl", "#!/bin/sh\nexit 3\n")     # ufw inactive
        self.command("omarchy-launch-floating-terminal-with-presentation",
                     "#!/bin/sh\nprintf '%s\\n' \"$1\"\n")
        self.env = os.environ.copy()
        self.env.update(PATH=f"{self.bin}:{self.env['PATH']}",
                        OMDROP_DISCOVERABLE="/nonexistent",
                        OMDROP_RECEIVER_PYTHON=str(self.bin / "python3"),
                        OMDROP_SYSFS=apple_wifi_sysfs(self.tmp.name))

    def command(self, name, body):
        path = self.bin / name
        path.write_text(body)
        path.chmod(0o755)

    def build_script(self):
        result = subprocess.run([OMDROP, "install-driver"], env=self.env,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return OMDROP.read_text(), result.stdout

    def test_nothing_comes_from_the_aur(self):
        # The regression: `yay -S opendrop` resolves to whatever the AUR holds
        # at install time, which is not the code anyone reviewed. A pinned AUR
        # recipe was no better in practice: its own dependencies came from the
        # AUR too, and it stopped building when setuptools moved on.
        _, script = self.build_script()
        self.assertNotIn("yay -S", script)
        self.assertNotIn("paru -S", script)
        self.assertNotIn("aur.archlinux.org", script)

    def test_the_receiver_library_comes_from_the_official_repositories(self):
        # Without it the receiver cannot start, and the driver on its own does
        # not guarantee it. Installed by exact package name, never built.
        _, script = self.build_script()
        self.assertRegex(script, r"(?m)^sudo pacman -S --needed --asdeps python-libarchive-c keyutils$")

    def test_the_pinned_commit_is_a_full_sha_used_literally(self):
        # Two places name the commit -- the constant a reader is shown, and
        # the literal the checkout uses, because a baseline scanner cannot
        # resolve a variable. They must not drift apart.
        source, script = self.build_script()
        declared = re.search(r"^DRIVER_COMMIT=([0-9a-f]{40})$", source, re.M)
        self.assertIsNotNone(declared, "DRIVER_COMMIT is not declared as a full SHA")
        self.assertIn(declared.group(1), script,
                      "DRIVER_COMMIT is not used literally in the install script")

    def test_a_failed_checkout_never_falls_through_to_a_build(self):
        # Fail-closed: a checkout that could not reach the pinned commit must
        # not build whatever the clone happens to be sitting on.
        _, script = self.build_script()
        builds = re.findall(r"^.*\bmakepkg\b.*$", script, re.M)
        self.assertTrue(builds, script)
        for line in builds:
            self.assertRegex(line, r"checkout --detach [0-9a-f]{40} && makepkg")

    def repository_carries(self, version):
        # `pacman -Si` answers from the sync databases on disk, which can be
        # older than this plugin's pin.
        self.command("pacman", f"""#!/bin/sh
[ "$1" = -Si ] && [ "$2" = brcmfmac-awdl-dkms ] || exit 1
printf 'Repository      : extra\\nName            : brcmfmac-awdl-dkms\\nVersion         : {version}\\n'
""")

    def test_a_repository_driver_at_the_pin_or_newer_is_installed_from_it(self):
        source = OMDROP.read_text()
        pin = re.search(r"(?m)^DRIVER_VERSION=(\S+)$", source).group(1)
        for version in (f"{pin}-1", f"{pin}-2", "99.0.0-1"):
            with self.subTest(version=version):
                self.repository_carries(version)
                _, script = self.build_script()
                self.assertRegex(script, r"(?m)^sudo pacman -S --needed --noconfirm brcmfmac-awdl-dkms$")
                self.assertNotIn("makepkg", script)

    def test_a_repository_driver_older_than_the_pin_is_never_installed(self):
        # The regression: any package by that name was taken, so a stale
        # database installed a driver older than the pinned one, without the
        # fixes the pin was raised for.
        for version in ("0.9.9-1", "0.1.0-3"):
            with self.subTest(version=version):
                self.repository_carries(version)
                _, script = self.build_script()
                self.assertNotIn("brcmfmac-awdl-dkms", script)
                self.assertRegex(script, r"checkout --detach [0-9a-f]{40} && makepkg")


if __name__ == "__main__":
    unittest.main()
