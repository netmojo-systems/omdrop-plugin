"""Run the panel's actual status/diagnostic JavaScript in Qt Quick Test.

Requires qmltestrunner (Qt Quick Test); skipped when it is unavailable.
No shell, radio, systemd or network services are started.
"""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNNER = os.environ.get("QMLTESTRUNNER") or shutil.which("qmltestrunner6") or shutil.which("qmltestrunner")


def block(source, marker):
    start = source.index("{", source.index(marker))
    depth = 1
    end = start + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


@unittest.skipUnless(RUNNER, "Qt Quick Test is not installed")
class PanelPrerequisiteTests(unittest.TestCase):
    def test_panel_recovers_from_changed_prerequisites(self):
        source = (ROOT / "Panel.qml").read_text()
        status = block(source, "function applyStatus(text)")
        doctor = block(source[source.index("id: doctorProc"):], "onStreamFinished:")
        detail = block(source, "readonly property string detailText:")
        usable = source.split("readonly property bool usable:", 1)[1].splitlines()[0]
        fixture = r"""
import QtQuick
import QtTest
TestCase {
  id: root
  name: "PanelPrerequisites"
  property bool installed: false
  property bool receiving: false
  property int visibility: -1
  property int remaining: -1
  property string deviceName: ""
  property string downloadDir: ""
  property string blockedReason: ""
  property bool soundOn: false
  property string audience: ""
  property int senders: 0
  property string shownName: "test"
  property string doctorText: ""
  property bool driverInstallable: false
  property bool busy: false
  property bool settling: false
  property string lastError: ""
  property string reasonText: ""
  property string visibleText: "visible"
  property QtObject doctorProc: QtObject { property bool running: false }
  property QtObject soundProc: QtObject { property bool running: false }
  property QtObject audienceProc: QtObject { property bool running: false }
  property QtObject nameField: QtObject {
    property bool activeFocus: false
    property string text: ""
  }
  readonly property bool usable: USABLE
  readonly property string detailText: DETAIL
  function syncWindowToRunning(mode) {}
  function applyStatus(text) STATUS
  function applyDoctor(text) DOCTOR
  function status(receiving, visible) {
    applyStatus(JSON.stringify({receiving: receiving, visible: visible}))
  }
  function diagnosis(id, say) {
    doctorProc.running = false
    applyDoctor(JSON.stringify({ready: !id, missing: id ? [{id: id, say: say}] : []}))
  }
  function init() {
    receiving = false; visibility = -1; installed = false
    doctorText = ""; driverInstallable = false; busy = false
    doctorProc.running = false
  }
  function test_backend_installed_outside_panel() {
    diagnosis("hardware", "Apple Broadcom required")
    status(false, null)
    verify(doctorProc.running, "Cached hardware warning must not suppress a new check")
    diagnosis("radio", "Use channel 6, 44 or 149")
    status(false, false)
    verify(doctorProc.running, "A present helper can still have unmet prerequisites")
    compare(detailText, "Use channel 6, 44 or 149")
  }
  function test_network_changed_outside_panel() {
    status(false, false)
    diagnosis("radio", "Use channel 6, 44 or 149")
    compare(detailText, "Use channel 6, 44 or 149")
    status(false, false)
    verify(doctorProc.running)
    diagnosis("", "")
    compare(detailText, "Nearby Apple devices cannot see this computer.")
  }
  function test_install_button_updates() {
    status(false, null)
    diagnosis("driver", "Install driver")
    verify(driverInstallable)
    status(false, false)
    diagnosis("radio", "Change channel")
    verify(!driverInstallable)
    compare(detailText, "Change channel")
  }
  function test_receiving_clears_old_warning() {
    diagnosis("driver", "Install driver")
    status(true, true)
    compare(doctorText, "")
    verify(!driverInstallable)
    verify(!doctorProc.running)
  }
  function test_busy_does_not_start_diagnostic() {
    busy = true
    status(false, false)
    verify(!doctorProc.running)
  }
  function test_diagnostic_in_flight_is_not_restarted() {
    status(false, false)
    verify(doctorProc.running)
    diagnosis("radio", "Channel blocked")
    doctorProc.running = true
    status(false, false)
    compare(doctorText, "Channel blocked")
    verify(doctorProc.running)
  }
}
"""
        for marker, value in (("USABLE", usable), ("DETAIL", detail),
                              ("STATUS", status), ("DOCTOR", doctor)):
            fixture = fixture.replace(marker, value)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tst_prerequisites.qml"
            path.write_text(fixture)
            result = subprocess.run(
                [RUNNER, "-input", str(path)],
                env=dict(os.environ, QT_QPA_PLATFORM="offscreen"),
                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
