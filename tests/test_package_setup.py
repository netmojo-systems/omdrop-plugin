"""`omdrop setup` links a packaged plugin into the shell's plugins.

The omdrop package installs the plugin under /usr/share/omdrop, and the shell
loads third-party plugins only from ~/.config/omarchy/plugins. setup links one
when the user agrees, which needs a terminal, and a replaced clone goes to
the trash, or is moved aside where that fails; it is never deleted. A copy
that isn't packaged never links itself.
OMDROP_PACKAGE_ROOT stands in for /usr.
"""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = shutil.which("script")


class PackageSetupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        tmp = Path(self.tmp.name).resolve()
        self.usr = tmp / "usr"
        # The plugin as the package lays it out.
        self.plugin = self.usr / "share" / "omdrop"
        shutil.copytree(ROOT, self.plugin, symlinks=True,
                        ignore=shutil.ignore_patterns(".git", "core", "tests", "omarchy-pkgs",
                                                      "__pycache__"))
        self.home = tmp / "home"
        self.home.mkdir()
        self.target = self.home / ".config" / "omarchy" / "plugins" / "netmojo.omdrop"
        self.bin = tmp / "bin"
        self.bin.mkdir()
        self.calls = tmp / "calls"
        log = '#!/bin/sh\nprintf "%s %s\\n" "$(basename "$0")" "$*" >> "$CALLS"\n'
        self.command("omarchy-shell", log)
        # ENABLE_RC makes adding the widget fail.
        self.command("omarchy-plugin-enable", log + 'exit "${ENABLE_RC:-0}"\n')
        # The receiver's unit installs; nothing is active.
        self.command("systemctl", '#!/bin/sh\ncase "$*" in *is-active*) exit 3 ;; esac\nexit 0\n')
        # `gio trash` moves its argument into the user's trash; GIO_RC makes
        # it fail and leave it, as gio does without a trash it can use, and
        # GIO_MOVED_RC makes it move it and still exit with that status.
        self.command("gio", log + '[ "$1" = trash ] && [ "${GIO_RC:-0}" = 0 ] || exit "${GIO_RC:-1}"\n'
                     'mkdir -p "$HOME/.local/share/Trash/files" && '
                     'mv "$2" "$HOME/.local/share/Trash/files/" && exit "${GIO_MOVED_RC:-0}"\n')
        self.env = {k: v for k, v in os.environ.items() if k != "OMDROP_IMPLEMENTATION"}
        self.env.update(PATH=f"{self.bin}:{self.env['PATH']}", HOME=str(self.home),
                        XDG_CONFIG_HOME=str(self.home / ".config"),
                        XDG_DATA_HOME=str(self.home / ".local" / "share"),
                        OMDROP_IMPLEMENTATION="python", OMDROP_PACKAGE_ROOT=str(self.usr),
                        CALLS=str(self.calls))

    def command(self, name, body):
        path = self.bin / name
        path.write_text(body)
        path.chmod(0o755)

    def setup_(self, plugin=None, **env):
        return subprocess.run([str((plugin or self.plugin) / "bin" / "omdrop"), "setup"],
                              env={**self.env, **env}, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=120)

    def calls_made(self):
        return self.calls.read_text() if self.calls.exists() else ""

    def previous_clone(self, version="0.0.1"):
        self.target.mkdir(parents=True)
        (self.target / "marker").write_text("git clone")
        (self.target / "manifest.json").write_text(f'{{"version": "{version}"}}\n')

    def packaged_version(self):
        return json.loads((self.plugin / "manifest.json").read_text())["version"]

    def test_a_packaged_plugin_is_linked_once_and_its_widget_added(self):
        run = self.setup_()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(Path(os.readlink(self.target)), self.plugin)
        self.assertIn("omarchy-shell shell rescanPlugins", self.calls_made())
        self.assertIn("omarchy-plugin-enable netmojo.omdrop", self.calls_made())
        self.assertEqual(self.setup_().returncode, 0)
        self.assertEqual(self.calls_made().count("omarchy-plugin-enable"), 1)

    def test_a_copy_that_is_not_packaged_links_nothing(self):
        run = self.setup_(OMDROP_PACKAGE_ROOT=str(Path(self.tmp.name) / "elsewhere"))
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertFalse(os.path.lexists(self.target))

    def test_a_previous_installation_is_kept_without_a_terminal(self):
        self.previous_clone()
        run = self.setup_()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual((self.target / "marker").read_text(), "git clone")
        self.assertIn("Run omdrop setup in a terminal to replace it", run.stderr)
        self.assertNotIn("omarchy-plugin-enable", self.calls_made())

    def terminal_setup(self, answer, **env):
        # script(1) gives setup the terminal its question needs.
        return subprocess.run([SCRIPT, "-qec", f"{self.plugin}/bin/omdrop setup", "/dev/null"],
                              env={**self.env, **env}, input=answer, capture_output=True,
                              text=True, timeout=120)

    def asides(self):
        return [p for p in self.target.parent.iterdir()
                if p.name.startswith(".netmojo.omdrop.replaced-")]

    @unittest.skipUnless(SCRIPT, "needs script(1)")
    def test_a_previous_installation_goes_to_the_trash_when_the_user_agrees(self):
        self.assert_trashed()

    @unittest.skipUnless(SCRIPT, "needs script(1)")
    def test_a_copy_the_trash_took_counts_even_when_gio_reports_failure(self):
        self.assert_trashed(GIO_MOVED_RC="1")

    def assert_trashed(self, **env):
        self.previous_clone()
        run = self.terminal_setup("\n", **env)
        self.assertEqual(run.returncode, 0, run.stdout)
        self.assertIn("Previous Omdrop plugin installation detected", run.stdout)
        self.assertIn(f"will replace it with a newer version (0.0.1 → {self.packaged_version()})",
                      run.stdout)
        self.assertIn("Moved the previous installation to the trash. Restore it from Files if needed.",
                      run.stdout)
        self.assertEqual(Path(os.readlink(self.target)), self.plugin)
        trashed = self.home / ".local" / "share" / "Trash" / "files" / "netmojo.omdrop"
        self.assertEqual((trashed / "marker").read_text(), "git clone")
        self.assertEqual(self.asides(), [])

    @unittest.skipUnless(SCRIPT, "needs script(1)")
    def test_a_previous_installation_the_trash_refuses_is_moved_aside(self):
        self.previous_clone()
        run = self.terminal_setup("\n", GIO_RC="1")
        self.assertEqual(run.returncode, 0, run.stdout)
        self.assertEqual(Path(os.readlink(self.target)), self.plugin)
        [aside] = self.asides()
        self.assertIn(f"Moved the previous installation to {aside}.", run.stdout)
        self.assertEqual((aside / "marker").read_text(), "git clone")

    @unittest.skipUnless(SCRIPT, "needs script(1)")
    def test_a_previous_installation_stays_when_the_user_declines(self):
        # A clone that follows main can be ahead of the packaged release.
        self.previous_clone(version="99.0.0")
        run = self.terminal_setup("n\n")
        self.assertIn(f"will replace it with version {self.packaged_version()} (installed: 99.0.0)",
                      run.stdout)
        self.assertEqual(run.returncode, 0, run.stdout)
        self.assertEqual((self.target / "marker").read_text(), "git clone")
        self.assertEqual(self.asides(), [])

    @unittest.skipUnless(SCRIPT, "needs script(1)")
    def test_end_of_input_keeps_the_previous_installation(self):
        # Ctrl-D at the question is No; only an empty line is Yes.
        self.previous_clone()
        run = self.terminal_setup("\x04")
        self.assertEqual(run.returncode, 0, run.stdout)
        self.assertEqual((self.target / "marker").read_text(), "git clone")
        self.assertEqual(self.asides(), [])

    def test_a_failed_widget_add_is_retried_until_it_works_and_not_after(self):
        run = self.setup_(ENABLE_RC="1")
        self.assertIn("The next omdrop setup tries again", run.stderr)
        self.setup_()
        self.setup_()
        # Once on the failed run, once when it worked, and never again: a user
        # who removes the widget keeps it removed.
        self.assertEqual(self.calls_made().count("omarchy-plugin-enable"), 2)

    def test_a_packaged_setup_leaves_the_path_link_alone(self):
        # /usr/bin/omdrop is the command. A link to an older copy keeps
        # pointing at the path under ~/.config, which the package's link
        # takes over once the user agrees.
        local_bin = self.home / ".local" / "bin"
        local_bin.mkdir(parents=True)
        old = self.target / "bin" / "omdrop"
        (local_bin / "omdrop").symlink_to(old)
        self.assertEqual(self.setup_().returncode, 0)
        self.assertEqual(Path(os.readlink(local_bin / "omdrop")), old)

    def test_a_fresh_packaged_setup_adds_no_path_link(self):
        self.assertEqual(self.setup_().returncode, 0)
        self.assertFalse(os.path.lexists(self.home / ".local" / "bin" / "omdrop"))


if __name__ == "__main__":
    unittest.main()
