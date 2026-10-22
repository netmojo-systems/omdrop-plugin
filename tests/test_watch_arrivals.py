"""Which of the receiver's log lines name an arrival, and which files they name.

`omdrop watch` reads the receiver's log, and a sender's text reaches that log:
a device name, a file name, a URL. The watcher used to take any line holding
`upload ...: stored ` and announce whatever followed, an absolute path
included, so a forged record could hand any of the user's files to the
clipboard and a notification. These tests hold bin/omdrop's arrival_names to
the rules of omdrop-core's links.rs (arrivals, resolve_arrivals,
arrived_file), whose own tests they mirror.
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OMDROP = ROOT / "bin" / "omdrop"
TS = "2026-10-10 16:14:20,098 INFO root: "


def arrival_names_function():
    source = OMDROP.read_text()
    start = source.index("arrival_names() {")
    return source[start:source.index("\n}\n", start) + 3]


class ArrivalNamesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.dir = self.root / "Downloads"
        self.dir.mkdir()
        self.outside = self.root / "secret.png"
        self.outside.write_text("x")

    def file(self, name):
        (self.dir / name).write_text("x")

    def names(self, journal):
        """What arrival_names prints for `journal` (bytes): one list of names
        per record that named a file, and its warnings."""
        result = subprocess.run(
            ["bash", "-c", arrival_names_function() + '\narrival_names "$1"', "_", str(self.dir)],
            input=journal, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        records = [line.split("/") for line in result.stdout.decode().splitlines()]
        return records, result.stderr.decode()

    def test_only_the_receivers_own_records_name_arrivals(self):
        for name in ("a.jpg", "b c.png", "Example.url"):
            self.file(name)
        journal = (f"{TS}upload 1A2B-3c_d.e: stored a.jpg, b c.png\n"
                   f"{TS}link stored as Example.url -> https://example.com/\n")
        self.assertEqual(self.names(journal.encode())[0],
                         [["a.jpg", "b c.png"], ["Example.url"]])

        self.file("a.webloc")
        for forged in (
            f"upload ABC: stored {self.outside}",
            f"upload ABC: stored a.jpg",
            f"{TS}GET /Discover from Mac upload X: stored a.jpg",
            f"{TS.replace('INFO', 'DEBUG')}upload X: stored a.jpg",
            f"x{TS}upload X: stored a.jpg",
            f"{TS}upload X Y: stored a.jpg",
            f"{TS}upload {'x' * 65}: stored a.jpg",
            f"{TS}upload : stored a.jpg",
            f"{TS}upload X: stored ",
            f"{TS}link stored as ../a.url -> https://e.x/",
            f"{TS}link stored as Example.url -> file:///etc/passwd",
            f"{TS}link stored as Example.url -> https://",
            f"{TS}link stored as Example.url -> https://e.x/\u2003a",
            f"{TS}link stored as Example.url -> HTTPS://e.x/",
            f"{TS}link stored as a.webloc -> https://e.x/",
            f"{TS}link stored as .url -> https://e.x/",
        ):
            with self.subTest(forged=forged):
                self.assertEqual(self.names((forged + "\n").encode())[0], [])

    def test_only_regular_files_directly_in_the_download_folder_are_acted_on(self):
        for name in ("a.jpg", "two, parts.txt", "b.png", ".hidden", "-rf.txt"):
            self.file(name)
        (self.dir / "link.png").symlink_to(self.outside)
        (self.dir / "sub").mkdir()
        (self.dir / "sub" / "c.png").write_text("x")

        records, _ = self.names(f"{TS}upload X: stored a.jpg, two, parts.txt, b.png, -rf.txt\n".encode())
        self.assertEqual(records, [["a.jpg", "two, parts.txt", "b.png", "-rf.txt"]])

        forged = f"{self.outside}, link.png, .hidden, sub/c.png, sub, gone.jpg, ../Downloads/a.jpg"
        records, warnings = self.names(f"{TS}upload X: stored {forged}\n".encode())
        self.assertEqual(records, [])
        self.assertEqual(warnings.count("which is not a file in"), 7, warnings)

        records, _ = self.names(f"{TS}link stored as link.url -> https://e.x/\n".encode())
        self.assertEqual(records, [])

    def test_a_name_with_a_control_character_is_not_a_file_name(self):
        # Rust's char::is_control: C0, DEL and C1.
        for bad in ("a\x1b[31m.jpg", "a\x7f.jpg", "a\u0085.jpg", "a\r.jpg"):
            with self.subTest(name=repr(bad)):
                self.file(bad)
                self.assertEqual(self.names(f"{TS}upload X: stored {bad}\n".encode())[0], [])

    def test_a_line_that_is_not_utf8_is_not_a_record(self):
        self.file("a.jpg")
        self.assertEqual(self.names(TS.encode() + b"upload X: stored a.jpg, \xff\n")[0], [])

    def test_the_last_line_counts_without_its_newline(self):
        self.file("a.jpg")
        self.assertEqual(self.names(f"{TS}upload X: stored a.jpg".encode())[0], [["a.jpg"]])


if __name__ == "__main__":
    unittest.main()
