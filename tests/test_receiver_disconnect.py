"""Keep network failures distinct from storage failures during an Upload."""

import errno
import io
import socket
import ssl
import tempfile
import types
import unittest
from http.server import BaseHTTPRequestHandler
from unittest.mock import Mock, patch

from test_receiver_limits import SERVE, receiver_namespace


class UploadFailureTests(unittest.TestCase):
    def setUp(self):
        self.ns = receiver_namespace()
        source = SERVE.read_text()
        self.ns.update(BaseHTTPRequestHandler=BaseHTTPRequestHandler, ssl=ssl,
                       contacts=types.SimpleNamespace(visibility=lambda: "everyone"),
                       MAX_RECEIVE_PERCENT=30)
        exec(source[source.index("class Handler("):
                    source.index("# ------------------------------------------------------------------ identity")],
             self.ns)
        self.dest = tempfile.TemporaryDirectory()
        self.addCleanup(self.dest.cleanup)
        self.ns["DEST"] = self.dest.name
        self.handler = object.__new__(self.ns["Handler"])
        self.handler.headers = {"Content-Type": "application/x-dvzip", "Content-Length": "4"}
        self.handler.path = "/Upload"
        self.handler.close_connection = False
        self.handler.request = Mock(spec=socket.socket)
        self.handler.rfile = io.BytesIO(b"data")
        self.handler.send_response = Mock()
        self.handler.send_header = Mock()
        self.handler.end_headers = Mock()

    def assert_slots_available(self):
        slots = self.ns["UPLOAD_SLOTS"]
        acquired = []
        try:
            for _ in range(self.ns["MAX_CONCURRENT_UPLOADS"]):
                self.assertTrue(slots.acquire(blocking=False))
                acquired.append(True)
        finally:
            for _ in acquired:
                slots.release()

    def test_network_read_errors_close_temporary_file_without_a_response(self):
        for error in (ConnectionResetError(errno.ECONNRESET, "reset"),
                      ssl.SSLEOFError("TLS peer closed")):
            with self.subTest(error=type(error).__name__):
                raw = tempfile.TemporaryFile()
                self.handler.rfile = Mock(spec=io.BytesIO)
                self.handler.rfile.read1.side_effect = [b"da", error]
                with patch.object(tempfile, "TemporaryFile", return_value=raw):
                    with self.assertLogs(level="INFO") as logs:
                        self.handler.handle_upload()
                self.assertTrue(raw.closed)
                self.assertTrue(self.handler.close_connection)
                self.handler.send_response.assert_not_called()
                self.assertIn("peer disconnected", "\n".join(logs.output))
                self.assertIn("2 HTTP body/framing bytes read", "\n".join(logs.output))
                self.assert_slots_available()

    def test_disk_write_failure_still_returns_507_and_releases_resources(self):
        with tempfile.TemporaryFile() as backing:
            class FullDisk:
                def __enter__(self):
                    return self

                def __exit__(self, *_args):
                    backing.close()

                def fileno(self):
                    return backing.fileno()

                def write(self, _data):
                    raise OSError(errno.ENOSPC, "No space left on device")

            with patch.object(tempfile, "TemporaryFile", return_value=FullDisk()):
                with self.assertLogs(level="WARNING") as logs:
                    self.handler.handle_upload()
            self.assertTrue(backing.closed)
        self.handler.send_response.assert_called_once_with(507)
        self.assertIn("storage failed", "\n".join(logs.output))
        self.assert_slots_available()

    def test_disconnected_reply_is_not_retried(self):
        with patch.object(BaseHTTPRequestHandler, "handle_one_request",
                          side_effect=BrokenPipeError(errno.EPIPE, "broken pipe")):
            with self.assertLogs(level="INFO"):
                self.handler.handle_one_request()
        self.assertTrue(self.handler.close_connection)
        self.handler.send_response.assert_not_called()

    def test_disconnect_during_upload_wait_closes_without_a_response(self):
        for error in (ConnectionResetError(errno.ECONNRESET, "reset"),
                      ssl.SSLEOFError("TLS peer closed")):
            with self.subTest(error=type(error).__name__):
                self.handler.awaiting_upload = True
                self.handler.close_connection = False
                self.handler.rfile = Mock(spec=io.BufferedReader)
                self.handler.rfile.peek.side_effect = error
                with patch.object(BaseHTTPRequestHandler, "handle_one_request") as handle:
                    with self.assertLogs(level="INFO") as logs:
                        self.handler.handle_one_request()
                handle.assert_not_called()
                self.assertTrue(self.handler.close_connection)
                self.handler.send_response.assert_not_called()
                self.assertIn("peer disconnected", "\n".join(logs.output))

    def test_upload_wait_timeout_still_closes_without_dispatching(self):
        self.handler.awaiting_upload = True
        self.handler.rfile = Mock(spec=io.BufferedReader)
        self.handler.rfile.peek.side_effect = TimeoutError("timed out")
        with patch.object(BaseHTTPRequestHandler, "handle_one_request") as handle:
            with self.assertLogs(level="WARNING") as logs:
                self.handler.handle_one_request()
        handle.assert_not_called()
        self.assertTrue(self.handler.close_connection)
        self.handler.send_response.assert_not_called()
        self.assertIn("no Upload within", "\n".join(logs.output))


if __name__ == "__main__":
    unittest.main()
