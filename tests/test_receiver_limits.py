"""Resource ceilings for sender-controlled AirDrop request bodies and archives."""

import gzip
import io
import logging
import os
import re
import socket
import subprocess
import tempfile
import threading
import time
import types
import unittest
import unicodedata

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib
import zlib
from pathlib import Path

import libarchive


ROOT = Path(__file__).resolve().parents[1]
SERVE = ROOT / "bin" / "airdrop-serve.py"
CLI = ROOT / "bin" / "omdrop"


def receiver_namespace():
    """Load the pure receive helpers without starting the network service."""
    source = SERVE.read_text()
    start = source.index("KIB = 1024")
    end = source.index("\ndef store_link")
    namespace = {
        "io": io,
        "libarchive": libarchive,
        "logging": logging,
        "os": os,
        "re": re,
        "socket": socket,
        "tempfile": tempfile,
        "threading": threading,
        "time": time,
        "unicodedata": unicodedata,
        "zlib": zlib,
        "UNSAFE_CHAR": re.compile(
            r"[/\\\x00]|[\u2028\u2029\u202a-\u202e\u2066-\u2069\u200b-\u200f\ufeff]|[\x01-\x1f\x7f-\x9f]"
        ),
    }
    exec(source[start:end], namespace)
    namespace["MIN_FREE_BYTES"] = 0
    return namespace


def config_namespace():
    source = SERVE.read_text()
    start = source.index("def load_config")
    end = source.index("\ndef validate_download_dir")
    namespace = {
        "CONFIG_KEYS": ("name", "model", "download_dir", "max_receive_percent"),
        "STRING_CONFIG_KEYS": ("name", "model", "download_dir"),
        "re": re,
    }
    exec(source[start:end], namespace)
    return namespace


def cpio_bytes(files):
    # add_file_from_memory names members the same way in libarchive-c 2.9 to
    # 5.3; add_files(pathname=) is a TypeError in 2.9 and ignored in 5.1.
    with tempfile.TemporaryDirectory() as work:
        archive_path = Path(work) / "payload.cpio"
        with libarchive.file_writer(str(archive_path), "cpio") as archive:
            for name, data in files:
                archive.add_file_from_memory(name, len(data), data)
        return archive_path.read_bytes()


def stored_dvzip(payload):
    return (0x80000000 | len(payload)).to_bytes(4, "big") + payload


class ReceiverConfigTests(unittest.TestCase):
    def test_integer_receive_percentage_is_accepted(self):
        ns = config_namespace()
        with tempfile.NamedTemporaryFile("w", delete=False) as config:
            config.write('name = "Drop"\nmax_receive_percent = 45\n')
        self.addCleanup(os.unlink, config.name)

        loaded = ns["load_config"](config.name)

        self.assertEqual(loaded["max_receive_percent"], 45)

    def test_string_receive_percentage_is_rejected(self):
        ns = config_namespace()
        with tempfile.NamedTemporaryFile("w", delete=False) as config:
            config.write('max_receive_percent = "45"\n')
        self.addCleanup(os.unlink, config.name)

        with self.assertRaises(SystemExit):
            ns["load_config"](config.name)


class RequestBodyLimitTests(unittest.TestCase):
    def setUp(self):
        self.ns = receiver_namespace()

    def test_receive_budget_uses_configured_share_of_free_space(self):
        self.ns["MIN_FREE_BYTES"] = 100
        fake_fs = types.SimpleNamespace(f_bavail=1000, f_frsize=1)
        original = os.statvfs
        os.statvfs = lambda _path: fake_fs
        self.addCleanup(setattr, os, "statvfs", original)

        budget = self.ns["ReceiveBudget"]("/downloads", 30)

        self.assertEqual(budget.byte_limit, 300)
        self.assertEqual(budget.percent, 30)

    def test_content_length_over_limit_is_rejected_before_body_is_read(self):
        source = io.BytesIO(b"abcde")
        target = io.BytesIO()

        with self.assertRaises(self.ns["BodyTooLarge"]):
            self.ns["read_request_body"](
                source, {"Content-Length": "5"}, target, 4
            )

        self.assertEqual(source.tell(), 0)
        self.assertEqual(target.getvalue(), b"")

    def test_chunked_body_stops_before_chunk_that_crosses_limit(self):
        source = io.BytesIO(b"4\r\nabcd\r\n4\r\nefgh\r\n0\r\n\r\n")
        target = io.BytesIO()

        with self.assertRaises(self.ns["BodyTooLarge"]):
            self.ns["read_request_body"](
                source, {"Transfer-Encoding": "chunked"}, target, 7
            )

        self.assertEqual(target.getvalue(), b"abcd")

    def test_body_that_misses_progress_deadline_is_rejected(self):
        deadline = self.ns["ReadDeadline"]()
        deadline.started -= self.ns["INITIAL_READ_SECONDS"] + 1

        with self.assertRaises(socket.timeout):
            self.ns["read_request_body"](
                io.BytesIO(b"x"), {"Content-Length": "1"},
                io.BytesIO(), 1, deadline=deadline
            )

    def test_decompression_stops_at_ceiling(self):
        with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as target:
            source.write(gzip.compress(b"x" * 32))
            source.seek(0)

            with self.assertRaises(self.ns["UploadLimitError"]):
                self.ns["decode_dvzip"](source, target, 31)

            self.assertLessEqual(target.tell(), 31)


class StalledUploadTests(unittest.TestCase):
    """An iPhone that sends the whole body but never the closing 0 chunk."""

    def setUp(self):
        self.ns = receiver_namespace()
        self.dest = tempfile.TemporaryDirectory()
        self.addCleanup(self.dest.cleanup)
        self.ns["DEST"] = self.dest.name
        self.ns["PatientReader"].STEP = 0.2
        self.ns["READ_IDLE_TIMEOUT_SECONDS"] = 0.8
        self.body = stored_dvzip(cpio_bytes([("clip.mov", b"x" * 200000)]))

    def reader(self, raw):
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        check = lambda: self.ns["archive_is_complete"](raw, 10 ** 9)
        return self.ns["PatientReader"](a.makefile("rb"), a, check), b

    def read(self, raw, reader):
        return self.ns["read_request_body"](
            reader, {}, raw, 10 ** 9, plan=("chunked", None))

    def test_partial_line_survives_a_stall(self):
        reader, peer = self.reader(io.BytesIO())

        def send():
            peer.sendall(b"ab")
            time.sleep(0.5)
            peer.sendall(b"cd\n")
        threading.Thread(target=send).start()

        self.assertEqual(reader.readline(100), b"abcd\n")

    def test_complete_archive_without_closing_chunk_is_accepted(self):
        with tempfile.TemporaryFile() as raw:
            reader, peer = self.reader(raw)
            peer.sendall(b"%x\r\n" % len(self.body) + self.body + b"\r\n")

            with self.assertRaises(self.ns["BodyComplete"]):
                self.read(raw, reader)

    def test_archive_cut_between_members_is_not_complete(self):
        whole = cpio_bytes([("a.txt", b"a" * 600), ("b.txt", b"b" * 600)])
        # The first member ends where the second member's header starts.
        cut = whole.index(b"070707", 6)
        with tempfile.TemporaryFile() as raw:
            raw.write(stored_dvzip(whole[:cut]))
            self.assertFalse(self.ns["archive_is_complete"](raw, 10 ** 9))
            raw.seek(0)
            raw.truncate()
            raw.write(stored_dvzip(whole))
            self.assertTrue(self.ns["archive_is_complete"](raw, 10 ** 9))

    def test_empty_upload_is_not_complete(self):
        self.assertFalse(self.ns["archive_is_complete"](io.BytesIO(), 10 ** 9))

    def counting_reader(self, raw):
        calls = []
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)

        def check():
            calls.append(1)
            return self.ns["archive_is_complete"](raw, 10 ** 9)
        return self.ns["PatientReader"](a.makefile("rb"), a, check), b, calls

    def test_stall_inside_chunk_data_is_not_checked(self):
        with tempfile.TemporaryFile() as raw:
            reader, peer, calls = self.counting_reader(raw)
            # Announce the whole body, send half of it, then go quiet.
            peer.sendall(b"%x\r\n" % len(self.body) + self.body[:1000])

            with self.assertRaises(socket.timeout):
                self.read(raw, reader)
            self.assertEqual(calls, [])

    def test_checks_are_capped_per_upload(self):
        with tempfile.TemporaryFile() as raw:
            reader, peer, calls = self.counting_reader(raw)
            half = self.body[: len(self.body) // 2]
            step = self.ns["PatientReader"].STEP

            def trickle():
                # One small chunk per stall: every pause lands on a chunk
                # boundary, which is where checks are allowed.
                for i in range(5):
                    peer.sendall(b"%x\r\n" % 100 + half[i * 100:(i + 1) * 100] + b"\r\n")
                    time.sleep(step * 1.5)
            threading.Thread(target=trickle, daemon=True).start()

            with self.assertRaises(socket.timeout):
                self.read(raw, reader)
            self.assertEqual(len(calls), self.ns["PatientReader"].MAX_CHECKS)

    def test_falls_back_without_private_timeout_flag(self):
        class Raw:  # a SocketIO whose private flag was renamed
            pass

        class Reader:
            raw = Raw()

        rfile = Reader()
        self.assertIs(self.ns["patient_reader"](rfile, None, lambda: True), rfile)
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        real = a.makefile("rb")
        self.assertIsInstance(self.ns["patient_reader"](real, a, lambda: True),
                              self.ns["PatientReader"])

    def test_incomplete_archive_still_times_out(self):
        with tempfile.TemporaryFile() as raw:
            reader, peer = self.reader(raw)
            half = self.body[: len(self.body) // 2]
            peer.sendall(b"%x\r\n" % len(half) + half + b"\r\n")

            with self.assertRaises(socket.timeout):
                self.read(raw, reader)


class ArchiveExtractionLimitTests(unittest.TestCase):
    def setUp(self):
        self.ns = receiver_namespace()
        self.byte_limit = 1024 * 1024
        self.ns["MAX_ARCHIVE_MEMBERS"] = 32

    def store(self, files, dest):
        raw = io.BytesIO(stored_dvzip(cpio_bytes(files)))
        budget = types.SimpleNamespace(byte_limit=self.byte_limit)
        return self.ns["store_upload"](raw, dest, "transfer", budget)

    def test_successful_archive_is_streamed_to_files(self):
        with tempfile.TemporaryDirectory() as dest:
            written = self.store([("one.txt", b"one"), ("two.txt", b"two")], dest)

            self.assertEqual(written, ["one.txt", "two.txt"])
            self.assertEqual((Path(dest) / "one.txt").read_bytes(), b"one")
            self.assertEqual((Path(dest) / "two.txt").read_bytes(), b"two")

    def test_member_limit_removes_files_already_extracted(self):
        self.ns["MAX_ARCHIVE_MEMBERS"] = 1
        with tempfile.TemporaryDirectory() as dest:
            with self.assertRaises(self.ns["UploadLimitError"]):
                self.store([("one.txt", b"one"), ("two.txt", b"two")], dest)

            self.assertEqual(list(Path(dest).iterdir()), [])

    def test_per_file_limit_leaves_no_partial_output(self):
        self.byte_limit = 3
        with tempfile.TemporaryDirectory() as dest:
            with self.assertRaises(self.ns["UploadLimitError"]):
                self.store([("large.bin", b"four")], dest)

            self.assertEqual(list(Path(dest).iterdir()), [])

    def test_total_output_limit_removes_files_already_extracted(self):
        self.byte_limit = 5
        with tempfile.TemporaryDirectory() as dest:
            with self.assertRaises(self.ns["UploadLimitError"]):
                self.store([("one.bin", b"123"), ("two.bin", b"456")], dest)

            self.assertEqual(list(Path(dest).iterdir()), [])

    def test_limit_during_a_file_removes_that_partial_file(self):
        self.byte_limit = 3

        class Entry:
            isfile = True
            pathname = "partial.bin"
            size = 0

            @staticmethod
            def get_blocks():
                return iter((b"12", b"34"))

        class Archive:
            def __enter__(self):
                return iter((Entry(),))

            def __exit__(self, *_args):
                return False

        original = libarchive.stream_reader
        libarchive.stream_reader = lambda _stream: Archive()
        self.addCleanup(setattr, libarchive, "stream_reader", original)
        budget = types.SimpleNamespace(byte_limit=self.byte_limit)
        raw = io.BytesIO(stored_dvzip(b"decoded"))

        with tempfile.TemporaryDirectory() as dest:
            with self.assertRaises(self.ns["UploadLimitError"]):
                self.ns["store_upload"](raw, dest, "transfer", budget)

            self.assertEqual(list(Path(dest).iterdir()), [])

    def test_invalid_archive_is_not_saved_as_an_untrusted_raw_file(self):
        budget = types.SimpleNamespace(byte_limit=self.byte_limit)
        raw = io.BytesIO(stored_dvzip(b"not an archive"))
        with tempfile.TemporaryDirectory() as dest:
            with self.assertRaises(Exception):
                self.ns["store_upload"](raw, dest, "transfer", budget)

            self.assertEqual(list(Path(dest).iterdir()), [])


class LimitCommandTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        (root / "home").mkdir()
        fake_bin = root / "bin"
        fake_bin.mkdir()
        systemctl = fake_bin / "systemctl"
        systemctl.write_text("#!/bin/sh\nexit 3\n")
        systemctl.chmod(0o755)
        self.config = root / "config"
        self.env = os.environ.copy()
        self.env.update({
            "HOME": str(root / "home"),
            "XDG_CONFIG_HOME": str(self.config),
            "PATH": f"{fake_bin}:{self.env['PATH']}",
        })

    def run_limit(self, *args, check=True):
        return subprocess.run(
            [str(CLI), "limit", *args],
            env=self.env, text=True, capture_output=True, check=check
        )

    def test_default_and_configured_percentage(self):
        self.assertEqual(self.run_limit().stdout, "30%\n")

        result = self.run_limit("45")

        self.assertIn("45%", result.stdout)
        with (self.config / "airdrop" / "config.toml").open("rb") as config:
            self.assertEqual(tomllib.load(config)["max_receive_percent"], 45)
        self.assertEqual(self.run_limit().stdout, "45%\n")

    def test_percentage_outside_safe_range_is_rejected(self):
        result = self.run_limit("91", check=False)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("integer from 1 to 90", result.stderr)


if __name__ == "__main__":
    unittest.main()
