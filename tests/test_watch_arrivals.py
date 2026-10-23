"""Which of the receiver's log lines name an arrival, and which files they name.

`omdrop watch` reads the receiver's log, and a sender's text reaches that log:
a device name, a file name, a URL. The watcher used to take any line holding
`upload ...: stored ` and announce whatever followed, an absolute path
included, so a forged record could hand any of the user's files to the
clipboard and a notification. These tests hold bin/omdrop's arrival_names to
the rules of omdrop-core's links.rs (arrivals, arrived_file), whose own tests
they mirror.

A record names one file: `upload TID: stored NAME` for an upload of one,
`upload TID (K/N): stored NAME` for file K of N. The receiver used to join an
upload's names with ", ", which a name may hold too, and the watcher rejoined
pieces until one existed: "private.png, sent.txt" next to an existing
"private.png" announced private.png.
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

    def records(self, journal):
        """What arrival_names prints for `journal` (bytes): a (state, names)
        pair per line, and its warnings."""
        result = subprocess.run(
            ["bash", "-c", arrival_names_function() + '\narrival_names "$1"', "_", str(self.dir)],
            input=journal, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = [line.split("/") for line in result.stdout.decode().splitlines()]
        for fields in lines:
            self.assertIn(fields[0], ("more", "done"), lines)
        return [(fields[0], fields[1:]) for fields in lines], result.stderr.decode()

    def names(self, journal):
        """One list of names per record that named a file, and the warnings."""
        records, warnings = self.records(journal)
        return [names for _, names in records if names], warnings

    def test_only_the_receivers_own_records_name_arrivals(self):
        for name in ("a.jpg", "b c.png", "Example.url"):
            self.file(name)
        journal = (f"{TS}upload 1A2B-3c_d.e (1/2): stored a.jpg\n"
                   f"{TS}upload 1A2B-3c_d.e (2/2): stored b c.png\n"
                   f"{TS}link stored as Example.url -> https://example.com/\n")
        self.assertEqual(self.names(journal.encode())[0],
                         [["a.jpg"], ["b c.png"], ["Example.url"]])

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

        good = ["a.jpg", "two, parts.txt", "b.png", "-rf.txt"]
        records, _ = self.names(per_file("X", good).encode())
        self.assertEqual(records, [[name] for name in good])

        forged = [str(self.outside), "link.png", ".hidden", "sub/c.png", "sub", "gone.jpg",
                  "../Downloads/a.jpg"]
        records, warnings = self.names(per_file("X", forged).encode())
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
        self.assertEqual(self.names(TS.encode() + b"upload X: stored a.jpg\xff\n")[0], [])

    def test_the_last_line_counts_without_its_newline(self):
        self.file("a.jpg")
        self.assertEqual(self.names(f"{TS}upload X: stored a.jpg".encode())[0], [["a.jpg"]])

    def test_a_name_holding_a_comma_is_one_name(self):
        # The regression: the name was split on ", " and its first piece,
        # an unrelated file that exists, was announced instead.
        self.file("private.png")
        self.file("private.png, sent.txt")
        records, warnings = self.records(f"{TS}upload X: stored private.png, sent.txt\n".encode())
        self.assertEqual(records, [("done", ["private.png, sent.txt"])])
        self.assertEqual(warnings, "")

        (self.dir / "private.png, sent.txt").unlink()
        records, warnings = self.records(f"{TS}upload X: stored private.png, sent.txt\n".encode())
        self.assertEqual(records, [])
        self.assertIn("private.png, sent.txt", warnings)

    def test_an_upload_of_two_files_is_two_records(self):
        for name in ("a.jpg", "b, c.png"):
            self.file(name)
        records, _ = self.records(per_file("X", ["a.jpg", "b, c.png"]).encode())
        self.assertEqual(records, [("more", ["a.jpg"]), ("done", ["b, c.png"])])

    def test_an_upload_of_200_files_is_announced_whole(self):
        names = [f"{n:03d}-" + "x" * 190 + ".jpg" for n in range(200)]
        for name in names:
            self.file(name)

        records, warnings = self.records(per_file("ABC", names).encode())

        self.assertEqual(warnings, "")
        self.assertEqual([state for state, _ in records], ["more"] * 199 + ["done"])
        self.assertEqual([n for _, names in records for n in names], names)

    def test_an_upload_of_no_files_names_none(self):
        self.assertEqual(self.records(f"{TS}upload X: stored \n".encode()), ([], ""))

    def test_a_transfer_is_done_at_its_last_record_even_if_that_names_no_file(self):
        self.file("a.jpg")
        journal = (f"{TS}upload X (1/2): stored a.jpg\n"
                   f"{TS}upload X (2/2): stored gone.jpg\n")
        self.assertEqual(self.records(journal.encode())[0],
                         [("more", ["a.jpg"]), ("done", [])])

    def test_a_transfer_that_named_no_file_is_never_done(self):
        journal = (f"{TS}upload X (1/2): stored gone.jpg\n"
                   f"{TS}upload X (2/2): stored gone2.jpg\n"
                   f"{TS}upload Y: stored gone3.jpg\n")
        self.assertEqual(self.records(journal.encode())[0], [])

    def test_other_transfers_do_not_complete_one(self):
        for name in ("a.jpg", "b.jpg"):
            self.file(name)
        journal = (f"{TS}upload X (1/2): stored a.jpg\n"
                   f"{TS}upload Y (1/2): stored b.jpg\n"
                   f"{TS}upload Y (2/2): stored gone.jpg\n")
        self.assertEqual(self.records(journal.encode())[0],
                         [("more", ["a.jpg"]), ("more", ["b.jpg"]), ("done", [])])

    def test_only_well_formed_record_numbers_count(self):
        self.file("a.jpg")
        for head in ("X (0/1)", "X (2/1)", "X (1/513)", "X (01/2)", "X (1/02)", "X ( 1/2)",
                     "X (1/2 )", "X  (1/2)", "X(1/2)", "(1/2)", "X (1/2)(1/2)", "X (-1/2)",
                     "X (1/+2)", "X (1/2) ", f"{'x' * 65} (1/2)", "X (\u0661/2)"):
            with self.subTest(head=head):
                self.assertEqual(self.records(f"{TS}upload {head}: stored a.jpg\n".encode())[0], [])
        self.assertEqual(self.records(f"{TS}upload X (512/512): stored a.jpg\n".encode())[0],
                         [("done", ["a.jpg"])])

    def test_a_numbered_record_inside_other_text_is_not_one(self):
        self.file("a.jpg")
        for forged in (f"{TS}GET /Discover from Mac upload X (1/1): stored a.jpg",
                       f"upload X (1/1): stored a.jpg",
                       f"x{TS}upload X (1/1): stored a.jpg",
                       f"{TS.replace('INFO', 'WARNING')}upload X (1/1): stored a.jpg"):
            with self.subTest(forged=forged):
                self.assertEqual(self.records((forged + "\n").encode())[0], [])


def per_file(tid, names):
    """The receiver's records for an upload of `names`: the plain form for
    one file, otherwise `upload TID (K/N): stored NAME` per file."""
    if len(names) == 1:
        return f"{TS}upload {tid}: stored {names[0]}\n"
    return "".join(f"{TS}upload {tid} ({k}/{len(names)}): stored {name}\n"
                   for k, name in enumerate(names, 1))


if __name__ == "__main__":
    unittest.main()
