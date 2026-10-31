"""omdrop-core is offered, never required, and installed from this plugin.

`doctor` lists it under `offers`, which never makes the plugin unready, on the
hardware core has been tested on. `install-core` installs the plugin's own
core/: from a repository that carries that version or newer, otherwise built
from core/ with makepkg in a terminal the user watches.
"""
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OMDROP = ROOT / "bin" / "omdrop"


def core_wanted():
    text = (ROOT / "core" / "PKGBUILD").read_text()
    ver = re.search(r"^pkgver=(\S+)$", text, re.M).group(1)
    rel = re.search(r"^pkgrel=(\S+)$", text, re.M).group(1)
    return f"{ver}-{rel}"


def probe_helper(backend, hardware=True):
    """An omdrop-discoverable: omdrop-awdl 0.9.x's (no probe) for None, else
    one whose probe names BACKEND, reports HARDWARE, and nothing missing."""
    if backend is None:
        return '#!/bin/sh\necho "usage: omdrop-discoverable start|stop|status" >&2\nexit 2\n'
    answer = json.dumps({"backend": backend, "version": "1.0.0", "contract": "0.7.0",
                         "hardware": hardware, "missing": []})
    return f"#!/bin/sh\n[ \"$1\" = probe ] || exit 2\ncat <<'EOF'\n{answer}\nEOF\n"


class InstallCoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        tmp = Path(self.tmp.name)
        self.bin = tmp / "bin"
        self.bin.mkdir()
        # pacman answers from CORE_INSTALLED (pacman -Q), CORE_REPO (pacman
        # -Si) and CORE_OWNER (pacman -Qqo, the package OMDROP_CORE is
        # from); unset means absent.
        self.command("pacman", """#!/bin/sh
if [ "$1" = -Qqo ]; then [ -n "$CORE_OWNER" ] || exit 1; echo "$CORE_OWNER"; exit 0; fi
[ "$2" = omdrop-core ] || exit 1
case "$1" in
  -Q) [ -n "$CORE_INSTALLED" ] || exit 1; echo "omdrop-core $CORE_INSTALLED" ;;
  -Si) [ -n "$CORE_REPO" ] || exit 1
       printf 'Repository      : extra\\nName            : omdrop-core\\nVersion         : %s\\n' "$CORE_REPO" ;;
  *) exit 1 ;;
esac
""")
        # The receiver's unit is installed; RECEIVING makes it active.
        self.command("systemctl", """#!/bin/sh
case "$*" in
  *is-active*airdrop-receiver*) [ -n "$RECEIVING" ] && { echo active; exit 0; }; echo inactive; exit 3 ;;
  *is-active*) exit 3 ;;
esac
exit 0
""")
        self.command("omarchy-launch-floating-terminal-with-presentation",
                     "#!/bin/sh\nprintf '%s\\n' \"$1\"\n")
        self.broadcom = tmp / "sys" / "bus" / "pci" / "devices" / "0000:01:00.0"
        self.broadcom.mkdir(parents=True)
        (self.broadcom / "vendor").write_text("0x14e4\n")
        (self.broadcom / "class").write_text("0x028000\n")
        self.devicetree = tmp / "sys" / "firmware" / "devicetree" / "base" / "compatible"
        self.devicetree.parent.mkdir(parents=True)
        self.devicetree.write_bytes(b"apple,j293\0apple,t8103\0apple,arm-platform\0")
        self.backend(None)
        self.env = {k: v for k, v in os.environ.items()
                    if k not in ("OMDROP_IMPLEMENTATION", "CORE_INSTALLED", "CORE_REPO",
                                 "CORE_OWNER", "RECEIVING", "XDG_BIN_HOME")}
        self.env.update(PATH=f"{self.bin}:{self.env['PATH']}",
                        HOME=str(tmp),
                        XDG_CONFIG_HOME=str(tmp / ".config"),
                        XDG_CACHE_HOME=str(tmp / ".cache"),
                        OMDROP_SYSFS=str(tmp / "sys"),
                        OMDROP_CORE="/nonexistent",
                        OMDROP_DISCOVERABLE=str(self.bin / "omdrop-discoverable"))

    def command(self, name, body):
        path = self.bin / name
        path.write_text(body)
        path.chmod(0o755)

    def backend(self, name, hardware=True):
        self.command("omdrop-discoverable", probe_helper(name, hardware))

    def no_broadcom(self):
        (self.broadcom / "vendor").write_text("0x8086\n")

    def intel_mac(self):
        # Broadcom Wi-Fi, but no Apple Silicon device tree.
        self.devicetree.unlink()

    def omdrop(self, *args):
        return subprocess.run([OMDROP, *args], env=self.env, capture_output=True, text=True)

    def doctor(self):
        result = self.omdrop("doctor", "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def install(self):
        result = self.omdrop("install-core")
        return result.returncode, result.stdout + result.stderr

    # --- doctor ---------------------------------------------------------------

    def test_core_is_offered_on_broadcom_and_never_blocks(self):
        for backend in (None, "awdl"):
            with self.subTest(backend=backend):
                self.backend(backend)
                doctor = self.doctor()
                self.assertEqual([o["id"] for o in doctor["offers"]], ["core"], doctor)
                self.assertIn("omdrop install-core", doctor["offers"][0]["say"])
                self.assertNotIn("core", [m["id"] for m in doctor["missing"]])

    def test_a_ready_plugin_stays_ready_with_core_on_offer(self):
        self.backend("awdl")
        doctor = self.doctor()
        self.assertTrue(doctor["ready"], doctor)
        self.assertTrue(doctor["offers"], doctor)

    def test_core_is_not_offered_where_it_is_untested(self):
        self.backend("owl")
        self.assertEqual(self.doctor()["offers"], [])
        self.backend("awdl", hardware=False)
        self.assertEqual(self.doctor()["offers"], [])
        self.backend(None)
        self.no_broadcom()
        self.assertEqual(self.doctor()["offers"], [])
        self.broadcom.joinpath("vendor").write_text("0x14e4\n")
        self.intel_mac()
        self.assertEqual(self.doctor()["offers"], [])

    def test_core_is_not_offered_to_someone_who_chose_python(self):
        self.env["OMDROP_IMPLEMENTATION"] = "python"
        self.assertEqual(self.doctor()["offers"], [])

    def test_core_is_not_offered_once_installed(self):
        self.env["CORE_INSTALLED"] = core_wanted()
        self.assertEqual(self.doctor()["offers"], [])

    def test_the_text_doctor_lists_the_offer_apart_from_blockers(self):
        out = self.omdrop("doctor").stdout
        self.assertRegex(out, r"(?s)\nTo do:\n  - omdrop-core.*going away.*omdrop install-core")

    def old_core(self, owner=None, hooks=True):
        # An installed core that answers `version` with one older than
        # CORE_MIN, beside a radio backend that ships core's hooks.
        core = self.bin / "core"
        core.write_text("#!/bin/sh\necho 'omdrop-core 0.0.1'\nexit 7\n")
        core.chmod(0o755)
        self.env["OMDROP_CORE"] = str(core)
        radio = Path(self.tmp.name) / "radio"
        radio.mkdir(exist_ok=True)
        if hooks:
            (radio / "probe").write_text("#!/bin/sh\nexit 0\n")
            (radio / "probe").chmod(0o755)
        self.env["OMDROP_HOOKS"] = str(radio)
        if owner:
            self.env["CORE_OWNER"] = owner

    def test_a_core_too_old_for_this_plugin_is_reported_and_blocks_nothing(self):
        # omdrop-awdl's hooks, whose probe reports nothing missing, so the
        # radio this machine happens to have or lack is out of the answer.
        self.backend("awdl")
        self.old_core(owner="omdrop-core")
        self.env["CORE_INSTALLED"] = "0.0.1-1"
        doctor = self.doctor()
        self.assertTrue(doctor["ready"], doctor)
        self.assertEqual([o["id"] for o in doctor["offers"]], ["core"], doctor)
        say = doctor["offers"][0]["say"]
        self.assertIn("The installed omdrop-core (0.0.1) is older than the", say)
        self.assertIn("running its Python version instead", say)
        self.assertTrue(say.endswith("Update it with: omdrop install-core"), say)

    def test_a_too_old_core_from_another_package_names_that_package(self):
        for owner, update in (("omdrop-owl", "Update the omdrop-owl package, which provides it."),
                              (None, "Update the package that provides it.")):
            with self.subTest(owner=owner):
                self.env.pop("CORE_OWNER", None)
                self.old_core(owner=owner)
                say = self.doctor()["offers"][0]["say"]
                self.assertTrue(say.endswith(update), say)
                self.assertNotIn("install-core", say)

    def test_core_without_a_backend_with_hooks_points_at_the_driver(self):
        # omdrop-awdl before 0.10.0 ships no hooks: core is installed (here
        # by the omdrop package) and current, but gets no commands.
        self.backend(None)
        self.old_core(owner="omdrop", hooks=False)
        doctor = self.doctor()
        self.assertEqual([o["id"] for o in doctor["offers"]], ["core"], doctor)
        self.assertTrue(doctor["offers"][0]["say"].endswith("Update it with: omdrop install-driver"),
                        doctor["offers"][0]["say"])

    def test_core_without_hooks_on_another_backend_offers_nothing(self):
        # A backend with no hooks, which isn't the user's to fix.
        self.backend("owl")
        self.old_core(owner="omdrop", hooks=False)
        self.assertEqual(self.doctor()["offers"], [])

    def test_install_core_leaves_a_packaged_core_to_the_package(self):
        self.old_core(owner="omdrop")
        code, out = self.install()
        self.assertEqual(code, 1, out)
        self.assertIn("comes with the omdrop package", out)
        self.assertNotIn("makepkg", out)

    def test_a_core_package_from_before_the_move_off_path_is_offered_as_an_update(self):
        # omdrop-core 0.1.2 and older installed /usr/bin/omdrop and nothing at
        # OMDROP_CORE: no hand-off, and install-core replaces the package.
        self.backend("awdl")
        self.env["CORE_INSTALLED"] = "0.1.1-1"
        doctor = self.doctor()
        self.assertTrue(doctor["ready"], doctor)
        self.assertEqual([o["id"] for o in doctor["offers"]], ["core"], doctor)
        say = doctor["offers"][0]["say"]
        self.assertIn("The installed omdrop-core (0.1.1-1) is older than the", say)
        self.assertTrue(say.endswith("Update it with: omdrop install-core"), say)
        self.assertNotIn("not installed", say)

    def test_core_is_installed_off_path_where_the_plugin_looks(self):
        # The plugin's omdrop is the one command on PATH, so it decides
        # whether core runs. The package puts core's omdrop beside its other
        # programs, where the plugin looks, and nothing in /usr/bin.
        self.assertRegex(OMDROP.read_text(),
                         r'(?m)^OMDROP_CORE="\$\{OMDROP_CORE:-/usr/lib/omdrop-core/omdrop\}"$')
        pkgbuild = (ROOT / "core" / "PKGBUILD").read_text()
        self.assertRegex(pkgbuild, r'(?m)^  local lib="\$\{pkgdir\}/usr/lib/omdrop-core" prog$')
        self.assertRegex(pkgbuild, r'(?m)^  for prog in omdrop .*; do$')
        self.assertNotIn("${pkgdir}/usr/bin", pkgbuild)

    # --- install-core ---------------------------------------------------------

    def test_without_a_repository_package_it_builds_this_plugins_core(self):
        code, out = self.install()
        self.assertEqual(code, 0, out)
        builds = re.findall(r"^.*\bmakepkg\b.*$", out, re.M)
        self.assertEqual(len(builds), 1, out)
        self.assertIn(f"--dir {ROOT / 'core'} ", builds[0])
        self.assertIn("--install", builds[0])
        # The build tree goes to the cache, never into the plugin's clone.
        cache = Path(self.env["XDG_CACHE_HOME"]) / "omdrop" / "omdrop-core"
        self.assertIn(f"BUILDDIR={cache}/build PKGDEST={cache} ", builds[0])
        self.assertNotIn("pacman -S", out)

    def test_a_repository_with_this_version_or_newer_is_used_instead(self):
        for repo in (core_wanted(), "99.0.0-1"):
            with self.subTest(repo=repo):
                self.env["CORE_REPO"] = repo
                code, out = self.install()
                self.assertEqual(code, 0, out)
                self.assertRegex(out, r"(?m)^sudo pacman -S --needed omdrop-core$")
                self.assertNotIn("makepkg", out)

    def test_an_older_repository_package_is_not_installed(self):
        self.env["CORE_REPO"] = "0.0.1-1"
        code, out = self.install()
        self.assertEqual(code, 0, out)
        self.assertNotIn("pacman -S", out)
        self.assertIn("makepkg", out)

    def test_a_current_install_has_nothing_to_do(self):
        self.env["CORE_INSTALLED"] = core_wanted()
        code, out = self.install()
        self.assertEqual(code, 0, out)
        self.assertIn("Nothing to do", out)
        self.assertNotIn("makepkg", out)

    def test_an_older_install_is_updated(self):
        self.env["CORE_INSTALLED"] = "0.0.1-1"
        code, out = self.install()
        self.assertEqual(code, 0, out)
        self.assertIn("makepkg", out)

    # The package puts nothing on PATH, and replacing a core that was
    # /usr/bin/omdrop removes that command, so install-core links the plugin's.

    def link(self):
        return Path(self.env["HOME"]) / ".local" / "bin" / "omdrop"

    def test_it_puts_the_plugins_command_on_path_before_installing(self):
        self.env["CORE_INSTALLED"] = "0.1.1-1"
        code, out = self.install()
        self.assertEqual(code, 0, out)
        self.assertEqual(os.readlink(self.link()), str(ROOT / "bin" / "omdrop"))
        said = f"Put the omdrop command on your PATH at {self.link()}."
        self.assertIn(said, out)
        self.assertLess(out.index(said), out.index("Opening a terminal"), out)
        # Already in place: nothing to say.
        code, out = self.install()
        self.assertNotIn("Put the omdrop command", out)

    def test_the_link_does_not_wait_for_the_install_to_succeed(self):
        self.env["CORE_INSTALLED"] = "0.1.1-1"
        self.env["RECEIVING"] = "1"
        code, out = self.install()
        self.assertNotEqual(code, 0)
        self.assertEqual(os.readlink(self.link()), str(ROOT / "bin" / "omdrop"))

    def test_a_command_of_the_users_own_is_left_alone(self):
        self.link().parent.mkdir(parents=True)
        self.link().write_text("#!/bin/sh\necho mine\n")
        code, out = self.install()
        self.assertEqual(code, 0, out)
        self.assertFalse(self.link().is_symlink())
        self.assertEqual(self.link().read_text(), "#!/bin/sh\necho mine\n")
        self.assertIn(f"Left {self.link()} alone: it is not ours", out)
        self.assertIn("makepkg", out)

    def test_it_refuses_while_receiving(self):
        self.env["RECEIVING"] = "1"
        code, out = self.install()
        self.assertNotEqual(code, 0)
        self.assertIn("omdrop off", out)
        self.assertNotIn("makepkg", out)

    def test_it_refuses_where_core_is_untested(self):
        for setup in ("owl", "awdl-no-hardware", "no-broadcom", "intel-mac"):
            with self.subTest(setup=setup):
                if setup == "owl":
                    self.backend("owl")
                elif setup == "awdl-no-hardware":
                    self.backend("awdl", hardware=False)
                elif setup == "no-broadcom":
                    self.backend(None)
                    self.no_broadcom()
                else:
                    self.backend(None)
                    (self.broadcom / "vendor").write_text("0x14e4\n")
                    self.intel_mac()
                code, out = self.install()
                self.assertNotEqual(code, 0, out)
                self.assertNotIn("makepkg", out)
                self.assertNotIn("pacman -S", out)

    # --- the hand-off to core -------------------------------------------------

    def test_install_core_is_never_handed_to_an_installed_core(self):
        # A core built before install-core existed answers it with its usage.
        ran = Path(self.tmp.name) / "core-ran"
        self.command("old-core", f"#!/bin/sh\ntouch {ran}\necho 'usage: omdrop ...' >&2\nexit 1\n")
        self.env["OMDROP_CORE"] = str(self.bin / "old-core")
        for implementation in (None, "rust"):
            with self.subTest(implementation=implementation):
                if implementation is None:
                    self.env.pop("OMDROP_IMPLEMENTATION", None)
                else:
                    self.env["OMDROP_IMPLEMENTATION"] = implementation
                code, out = self.install()
                self.assertEqual(code, 0, out)
                self.assertIn("makepkg", out)
                self.assertFalse(ran.exists(), out)

    def test_install_core_runs_here_with_rust_chosen_and_no_core(self):
        self.env["OMDROP_IMPLEMENTATION"] = "rust"
        code, out = self.install()
        self.assertEqual(code, 0, out)
        self.assertIn("makepkg", out)

    def test_install_core_still_refuses_an_unknown_implementation(self):
        self.env["OMDROP_IMPLEMENTATION"] = "ruby"
        code, out = self.install()
        self.assertEqual(code, 2, out)
        self.assertIn("OMDROP_IMPLEMENTATION must be python or rust", out)
        self.assertNotIn("makepkg", out)


if __name__ == "__main__":
    unittest.main()
