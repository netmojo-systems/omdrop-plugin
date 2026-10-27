"""`bin/omdrop` hands every command to an installed omdrop-core it can use.

The panel, the PATH link and the systemd units all run this script, so this
one hand-off is what moves a user to core. It must pass the arguments through
untouched and keep `$0`, which core uses to find this plugin; it must stay out
of the way when `OMDROP_IMPLEMENTATION=python` asks for the bash, when core is
not installed, and when the installed core is older than CORE_MIN or will not
say its version; `rust` must not fall back silently; an unknown value is
refused; and it must never hand off to itself.
"""

import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OMDROP = ROOT / "bin" / "omdrop"
CORE_MIN = re.search(r"^CORE_MIN=(\S+)$", OMDROP.read_text(), re.M).group(1)


def older(version):
    """A version just below VERSION: its last number lowered, or dropped."""
    parts = [int(p) for p in version.split(".")]
    while parts and parts[-1] == 0:
        parts.pop()
    parts[-1] -= 1
    return ".".join(map(str, parts)) or "0"


class HandoffHarness(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.core = Path(self.tmp.name) / "omdrop-core"
        # A stand-in for /usr/lib/omdrop-core/omdrop: say its version as core does, then
        # report how it was called. An empty CORE_VERSION says none, and
        # CORE_HANGS makes `version` never return.
        self.core.write_text('#!/bin/bash\n'
                             '[ "$1" = version ] && [ -n "$CORE_HANGS" ] && exec sleep 60\n'
                             '[ -n "$CORE_VERSION" ] && echo "omdrop-core $CORE_VERSION"\n'
                             'printf "core argv0=%s args=" "$0"\n'
                             'printf "[%s]" "$@"\necho\nexit 7\n')
        self.core.chmod(0o755)
        self.env = {k: v for k, v in os.environ.items()
                    if k not in ("OMDROP_IMPLEMENTATION", "CORE_HANGS")}
        # A radio backend that ships omdrop-core's hooks, as omdrop-awdl
        # 0.10.0 does: without one, core gets nothing.
        self.hooks = Path(self.tmp.name) / "radio"
        self.hooks.mkdir()
        (self.hooks / "probe").write_text("#!/bin/sh\nexit 0\n")
        (self.hooks / "probe").chmod(0o755)
        self.env.update(OMDROP_CORE=str(self.core), CORE_VERSION=CORE_MIN,
                        OMDROP_HOOKS=str(self.hooks))

    def run_omdrop(self, *args, **env):
        return subprocess.run([str(OMDROP), *args], env={**self.env, **env},
                              cwd=self.tmp.name, capture_output=True, text=True, timeout=30)

    def assert_handed_off(self, run):
        self.assertEqual(run.returncode, 7, run.stderr)
        self.assertIn("core argv0", run.stdout)

    def assert_ran_here(self, run):
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertTrue(run.stdout.startswith("omdrop "), run.stdout)
        self.assertNotIn("core argv0", run.stdout)


class CoreHandoffTests(HandoffHarness):
    def test_installed_core_gets_the_command_and_its_args_untouched(self):
        run = self.run_omdrop("send", "--to", "a b", "x")
        self.assertEqual(run.returncode, 7, run.stderr)
        self.assertTrue(run.stdout.strip().endswith("args=[send][--to][a b][x]"), run.stdout)

    def test_installed_core_sees_this_script_as_argv0(self):
        # Core finds the plugin through the path it was run as. A shebang
        # script cannot see argv[0] (the kernel puts the interpreter there),
        # so a real executable stands in: Python keeps it in sys.orig_argv.
        # Asked its version first, `python3 version` runs the script of that
        # name in the working directory.
        (Path(self.tmp.name) / "version").write_text(f'print("omdrop-core {CORE_MIN}")\n')
        python = Path(sys.executable).resolve()
        run = self.run_omdrop("-c", "import sys; print(sys.orig_argv[0])",
                              OMDROP_CORE=str(python))
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.strip(), str(OMDROP))

    def test_a_core_at_the_minimum_or_newer_gets_the_command(self):
        for version in (CORE_MIN, CORE_MIN + ".1", "9.9.9"):
            with self.subTest(version=version):
                self.assert_handed_off(self.run_omdrop("version", CORE_VERSION=version))

    def test_a_core_older_than_the_minimum_gets_nothing(self):
        self.assert_ran_here(self.run_omdrop("version", CORE_VERSION=older(CORE_MIN)))

    def test_a_core_that_will_not_say_its_version_gets_nothing(self):
        self.assert_ran_here(self.run_omdrop("version", CORE_VERSION=""))

    def test_a_core_that_hangs_when_asked_its_version_gets_nothing(self):
        started = time.monotonic()
        self.assert_ran_here(self.run_omdrop("version", CORE_HANGS="1"))
        self.assertLess(time.monotonic() - started, 10)

    def test_python_keeps_the_bash(self):
        self.assert_ran_here(self.run_omdrop("version", OMDROP_IMPLEMENTATION="python"))

    def test_rust_uses_core(self):
        self.assert_handed_off(self.run_omdrop("version", OMDROP_IMPLEMENTATION="rust"))

    def test_a_backend_without_hooks_keeps_the_bash(self):
        # A backend without hooks (omdrop-owl before 0.4.0, or one that never
        # ships them): a core that came with the omdrop package must not
        # drive it.
        (self.hooks / "probe").unlink()
        self.assert_ran_here(self.run_omdrop("version"))

    def test_rust_without_hooks_is_an_error_not_a_fallback(self):
        (self.hooks / "probe").unlink()
        run = self.run_omdrop("version", OMDROP_IMPLEMENTATION="rust")
        self.assertEqual(run.returncode, 2)
        self.assertEqual(run.stdout, "")
        self.assertIn("installs no omdrop-core hooks", run.stderr)

    def test_rust_without_core_is_an_error_not_a_fallback(self):
        absent = str(Path(self.tmp.name) / "absent")
        run = self.run_omdrop("version", OMDROP_IMPLEMENTATION="rust", OMDROP_CORE=absent)
        self.assertEqual(run.returncode, 2)
        self.assertEqual(run.stdout, "")
        self.assertIn("omdrop-core is not installed", run.stderr)

    def test_rust_with_an_old_core_is_an_error_not_a_fallback(self):
        run = self.run_omdrop("version", OMDROP_IMPLEMENTATION="rust",
                              CORE_VERSION=older(CORE_MIN))
        self.assertEqual(run.returncode, 2)
        self.assertEqual(run.stdout, "")
        self.assertIn(f"older than the {CORE_MIN} this version of Omdrop needs", run.stderr)

    def test_an_unknown_value_is_refused(self):
        run = self.run_omdrop("version", OMDROP_IMPLEMENTATION="pyhton")
        self.assertEqual(run.returncode, 2)
        self.assertEqual(run.stdout, "")
        self.assertEqual(run.stderr,
                         'omdrop: OMDROP_IMPLEMENTATION must be python or rust, not "pyhton"\n')

    def test_no_core_installed_runs_the_bash(self):
        self.assert_ran_here(self.run_omdrop("version",
                                             OMDROP_CORE=str(Path(self.tmp.name) / "absent")))

    def test_a_core_path_that_is_this_script_does_not_loop(self):
        link = Path(self.tmp.name) / "omdrop"
        link.symlink_to(OMDROP)
        self.assert_ran_here(self.run_omdrop("version", OMDROP_CORE=str(link)))

    def test_the_plugin_hands_off_to_its_own_core(self):
        # A CORE_MIN above core/'s own version would send no command to the
        # core this plugin builds.
        cargo = (ROOT / "core" / "Cargo.toml").read_text()
        workspace = re.search(r'^\[workspace\.package\][^\[]*?^version = "([^"]+)"',
                              cargo, re.M | re.S).group(1)
        # Both are plain dotted numbers, so tuples order them as vercmp does.
        number = lambda v: tuple(int(p) for p in v.split("."))
        self.assertGreaterEqual(number(workspace), number(CORE_MIN),
                                f"core/ is {workspace}, CORE_MIN {CORE_MIN}")


class PanelRefreshTests(HandoffHarness):
    """Commands that change what the panel shows ask it to look again."""

    def setUp(self):
        super().setUp()
        # omarchy-shell as the shell answers IPC: log the call.
        bin_dir = Path(self.tmp.name) / "bin"
        bin_dir.mkdir()
        self.ipc_log = Path(self.tmp.name) / "ipc.log"
        shell = bin_dir / "omarchy-shell"
        shell.write_text(f'#!/bin/sh\necho "$*" >> {self.ipc_log}\n')
        shell.chmod(0o755)
        home = Path(self.tmp.name) / "home"
        home.mkdir()
        self.env.update(PATH=f"{bin_dir}:{os.environ['PATH']}", HOME=str(home),
                        XDG_CONFIG_HOME=str(home / ".config"))

    def refreshes(self):
        return self.ipc_log.read_text().splitlines() if self.ipc_log.exists() else []

    def test_a_state_change_through_core_refreshes_the_panel(self):
        run = self.run_omdrop("on", "--everyone")
        # Core's exit status and arguments are untouched.
        self.assertEqual(run.returncode, 7, run.stderr)
        self.assertTrue(run.stdout.strip().endswith("args=[on][--everyone]"), run.stdout)
        self.assertEqual(self.refreshes(), ["-q netmojo.omdrop refresh"])

    def test_core_still_sees_this_script_as_argv0_for_a_state_change(self):
        # As test_installed_core_sees_this_script_as_argv0, through the
        # subshell that waits to refresh: `python3 on` runs the file "on".
        (Path(self.tmp.name) / "version").write_text(f'print("omdrop-core {CORE_MIN}")\n')
        (Path(self.tmp.name) / "on").write_text("import sys; print(sys.orig_argv[0])\n")
        run = self.run_omdrop("on", OMDROP_CORE=str(Path(sys.executable).resolve()))
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.strip(), str(OMDROP))
        self.assertEqual(self.refreshes(), ["-q netmojo.omdrop refresh"])

    def test_status_does_not_refresh(self):
        # The panel's refresh runs `status`: refreshing from it would loop.
        self.assert_handed_off(self.run_omdrop("status", "--json"))
        self.assertEqual(self.refreshes(), [])

    def test_a_state_change_in_the_bash_refreshes_the_panel(self):
        run = self.run_omdrop("name", OMDROP_IMPLEMENTATION="python")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(self.refreshes(), ["-q netmojo.omdrop refresh"])

    def test_no_omarchy_shell_is_not_an_error(self):
        (Path(self.tmp.name) / "bin" / "omarchy-shell").unlink()
        self.assert_handed_off(self.run_omdrop("off"))


if __name__ == "__main__":
    unittest.main()
