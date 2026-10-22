"""What a nearby device sends cannot reach the log, or the disk, unbounded.

Anything in range can send to the receiver in Everyone mode, so every name,
header and link it carries is untrusted. These tests hold the Python receiver
to the rules omdrop-core follows for the same input: log lines escaped and
capped as core's log::escape() does them, and links checked and budgeted
before anything is written.
"""

import logging
import os
import plistlib
import re
import sys
import unittest

from test_receiver_protocol import SERVE, ReceiverFixture


def log_namespace():
    """The receiver's log escaping, without starting the network service."""
    source = SERVE.read_text()
    start = source.index("MAX_LOG_MESSAGE_BYTES = ")
    end = source.index("\n_log_handler = ")
    namespace = {"logging": logging, "re": re}
    exec(source[start:end], namespace)
    return namespace


FORGED = "2026-10-10 16:14:20,098 INFO root: upload X: stored /home/u/secret.png"


class LogEscapeTests(unittest.TestCase):
    """The vectors are omdrop-core's own (core/crates/omdrop-receiver/src/log.rs)."""

    def setUp(self):
        self.ns = log_namespace()

    def test_peer_text_cannot_start_a_line_or_hide_itself(self):
        escape = self.ns["escape_log"]
        out = escape(f"Mac\n{FORGED}\r\u0085\u2028\u202e")
        self.assertEqual(out, f"Mac\\x0a{FORGED}\\x0d\\x85\\u2028\\u202e")
        self.assertEqual(escape("café, ok"), "café, ok")
        self.assertEqual(escape("\x00\x1f\x7f\x9f\u200b\u200f\u2066\u2069\ufeff"),
                         "\\x00\\x1f\\x7f\\x9f\\u200b\\u200f\\u2066\\u2069\\ufeff")

    def test_messages_stay_under_journald_line_max(self):
        out = self.ns["escape_log"]("é" * 40_000)
        self.assertLess(len(out.encode()), 32 * 1024 + 40)
        self.assertTrue(out.endswith(" [... 47232 more bytes]"), out[-40:])

    def test_a_cut_never_splits_a_character(self):
        # One ASCII byte first puts a 2-byte "é" across the 32 KiB mark, so
        # the cut moves back one byte: 32 767 kept of 80 001.
        out = self.ns["escape_log"]("a" + "é" * 40_000)
        self.assertTrue(out.endswith(" [... 47234 more bytes]"), out[-40:])
        self.assertEqual(len(out.removesuffix(" [... 47234 more bytes]").encode()), 32_767)

    def test_a_traceback_is_escaped_with_its_record(self):
        formatter = self.ns["EscapingFormatter"]("%(levelname)s %(name)s: %(message)s")
        try:
            raise FileExistsError(f"evil\n{FORGED}")
        except FileExistsError:
            record = logging.LogRecord("root", logging.ERROR, __file__, 1,
                                       "exception while serving %s", ("peer",), sys.exc_info())
        line = formatter.format(record)
        self.assertNotIn("\n", line)
        self.assertIn(f"evil\\x0a{FORGED}", line)


class LogInjectionTests(ReceiverFixture):
    def ask(self, fields, headers=None):
        ask = {"SenderModelName": "MacBookPro18,3", "TransferType": {"files": 1},
               "Items": [], "Files": []}
        ask.update(fields)
        status, _ = self.post(self.connection(), "/Ask",
                              plistlib.dumps(ask, fmt=plistlib.FMT_BINARY), headers)
        self.assertEqual(status, 200)
        return self.log.read_text().splitlines()

    def test_a_forged_sender_name_cannot_start_a_log_line(self):
        lines = self.ask({"SenderComputerName": f"Mac\n{FORGED}\u2028"})
        self.assertFalse([line for line in lines if line.startswith(FORGED[:23])])
        self.assertTrue([line for line in lines
                         if f"ask from Mac\\x0a{FORGED}\\u2028 (" in line])

    def test_request_headers_are_logged_on_one_line(self):
        lines = self.ask({"SenderComputerName": "Headers"},
                         {"X-Forged": "INFO root: link stored as a.url -> https://evil.example/"})
        self.assertFalse([line for line in lines if line.startswith("X-Forged")])
        self.assertTrue([line for line in lines
                         if re.search(r"POST /Ask, headers:.*\\x0aX-Forged: INFO", line)])

    def test_a_long_sender_name_is_cut_at_the_cap(self):
        lines = self.ask({"SenderComputerName": "Long" + "A" * 100_000})
        [line] = [line for line in lines if "ask from LongAAAA" in line]
        self.assertLess(len(line.encode()), 32 * 1024 + 100)
        self.assertRegex(line, r" \[\.\.\. \d+ more bytes\]$")


class AskListingTests(ReceiverFixture):
    def ask(self, fields):
        ask = {"SenderModelName": "MacBookPro18,3", "TransferType": {"files": 1},
               "Items": [], "Files": []}
        ask.update(fields)
        status, _ = self.post(self.connection(), "/Ask",
                              plistlib.dumps(ask, fmt=plistlib.FMT_BINARY))
        return status, self.log.read_text().splitlines()

    def test_the_listing_names_at_most_512_files(self):
        files = [{"FileName": f"f{i:03}.txt", "FileType": "public.data", "FileSize": 1}
                 for i in range(600)]
        status, lines = self.ask({"SenderComputerName": "Many", "Files": files})
        self.assertEqual(status, 200)
        [line] = [line for line in lines if "ask from Many (" in line]
        self.assertIn("600 item(s)", line)
        self.assertIn("; f511.txt public.data 1B", line)
        self.assertNotIn("f512.txt", line)

    def test_an_ask_over_the_item_limit_is_refused_before_it_is_listed(self):
        status, lines = self.ask({"SenderComputerName": "TooMany",
                                  "Items": [f"https://example.com/{i}" for i in range(513)]})
        self.assertEqual(status, 413)
        self.assertFalse([line for line in lines if "ask from TooMany" in line])
        self.assertTrue([line for line in lines
                         if line.endswith("/Ask rejected: Ask exceeds 512-item limit")])

    def test_a_file_entry_that_is_not_a_dictionary_is_listed_not_fatal(self):
        status, lines = self.ask({"SenderComputerName": "Odd", "Files": ["x", 1]})
        self.assertEqual(status, 200)
        self.assertTrue([line for line in lines
                         if line.endswith("ask from Odd (MacBookPro18,3): type files, "
                                          "2 item(s): None None NoneB; None None NoneB")])


class LinkTests(ReceiverFixture):
    def links(self, items):
        ask = plistlib.dumps({"SenderComputerName": "Phone", "SenderModelName": "iPhone17,1",
                              "TransferType": {"links": 1}, "Items": items},
                             fmt=plistlib.FMT_BINARY)
        status, _ = self.post(self.connection(), "/Ask", ask)
        return status

    def stored(self, host):
        return sorted(p.name for p in self.out.iterdir() if p.name.startswith(host))

    def test_a_url_with_spaces_or_control_characters_is_not_stored(self):
        bad = {"space.example": "https://space.example/a b",
               "tab.example": "https://tab.example/a\tb",
               "newline.example": "https://newline.example/a\nIconFile=/etc/passwd",
               "nbsp.example": "https://nbsp.example/a\u00a0b",
               "nel.example": "https://nel.example/a\u0085b",
               "del.example": "https://del.example/a\x7fb"}
        self.assertEqual(self.links([*bad.values(), "https://good.example/ok"]), 200)
        for host in bad:
            self.assertEqual(self.stored(host), [], host)
        self.assertEqual(self.stored("good.example"), ["good.example-ok.url"])
        log = self.log.read_text()
        self.assertEqual(log.count("ask: ignoring item with control characters or spaces "), 6)

    def test_a_url_over_8192_bytes_is_not_stored(self):
        prefix = "https://edge.example/"
        at_cap = prefix + "b" * (8192 - len(prefix))
        over = "https://long.example/" + "a" * 8200
        self.assertEqual(self.links([at_cap, over]), 200)
        self.assertNotIn("-> https://long.example/", self.log.read_text())
        self.assertIn("ask: ignoring item longer than 8192 bytes 'https://long.example/aaa",
                      self.log.read_text())
        self.assertEqual((self.out / self.stored_as(at_cap)).read_text(),
                         f"[InternetShortcut]\nURL={at_cap}\n")

    def stored_as(self, url):
        names = re.findall(r"INFO root: link stored as (\S+) -> (\S+)$",
                           self.log.read_text(), re.M)
        [name] = [name for name, logged in names if logged == url]
        return name

    def test_a_long_path_segment_is_stored_under_a_trimmed_name(self):
        url = "https://trim.example/" + "c" * 400 + ".x"
        self.assertEqual(self.links([url, url + "#again"]), 200)
        first, second = self.stored_as(url), self.stored_as(url + "#again")
        self.assertEqual(len(first.encode()), 255)
        self.assertRegex(first, r"^trim\.example-c+\.url$")
        self.assertLessEqual(len(second.encode()), 255)
        self.assertRegex(second, r"^trim\.example-c+-1\.url$")

    def test_a_name_that_would_be_all_extension_falls_back_to_link(self):
        # "trim.example-<400 c>" splits at the host's dot, leaving an
        # extension too long for any stem: never a hidden ".example-ccc".
        url = "https://hidden.example/" + "d" * 400
        self.assertEqual(self.links([url]), 200)
        self.assertRegex(self.stored_as(url), r"^link(-\d+)?\.url$")
        self.assertEqual([p.name for p in self.out.iterdir() if p.name.startswith(".")], [])


GIB = 1 << 30

# Runs the receiver with os.statvfs reporting FREE bytes free in its download
# folder, so a test can put the disk near Omdrop's 1 GiB reserve without
# filling one. argv: download folder, FREE, then the receiver's own argv.
LOW_DISK = """
import os, runpy, sys
out, free = sys.argv[1], int(sys.argv[2])
real = os.statvfs
def statvfs(path):
    st = real(path)
    if os.path.realpath(path) != out:
        return st
    return os.statvfs_result((4096, 4096, st.f_blocks, free // 4096, free // 4096,
                              st.f_files, st.f_ffree, st.f_favail, st.f_flag, st.f_namemax))
os.statvfs = statvfs
sys.argv = sys.argv[3:]
runpy.run_path(sys.argv[0], run_name="__main__")
"""


class LowDiskFixture(ReceiverFixture):
    free_bytes = None

    @classmethod
    def receiver_command(cls, *argv):
        return [sys.executable, "-c", LOW_DISK, os.path.realpath(cls.out),
                str(cls.free_bytes), str(SERVE), *argv]

    def links(self, items):
        ask = plistlib.dumps({"SenderComputerName": "Phone", "SenderModelName": "iPhone17,1",
                              "TransferType": {"links": 1}, "Items": items},
                             fmt=plistlib.FMT_BINARY)
        before = sorted(p.name for p in self.out.iterdir())
        status, _ = self.post(self.connection(), "/Ask", ask)
        return status, sorted(set(p.name for p in self.out.iterdir()) - set(before))


class LinkBudgetTests(LowDiskFixture):
    # 8 KiB above the reserve: the budget is min(30 % of free, free - 1 GiB).
    free_bytes = GIB + 8192

    def url(self, shortcut_bytes):
        """A URL whose .url file is shortcut_bytes long."""
        prefix = "https://budget.example/a."
        overhead = len("[InternetShortcut]\nURL=\n")
        return prefix + "x" * (shortcut_bytes - overhead - len(prefix))

    def test_a_link_is_charged_its_bytes_and_4096_more(self):
        status, new = self.links([self.url(4097)])
        self.assertEqual((status, new), (507, []))
        self.assertIn("/Ask rejected: links need 8193 bytes; 30% of 1073750016 free bytes "
                      "allows 8192", self.log.read_text())
        status, new = self.links([self.url(4096)])
        self.assertEqual(status, 200)
        self.assertEqual(len(new), 1)

    def test_links_past_the_budget_are_refused_and_none_stored(self):
        # Each fits alone; together they do not, and nothing is written.
        status, new = self.links([self.url(1000), self.url(1000)])
        self.assertEqual((status, new), (507, []))
        self.assertIn("/Ask rejected: links need 10192 bytes", self.log.read_text())

    def test_a_links_ask_with_nothing_to_store_is_answered(self):
        status, new = self.links(["ftp://budget.example/a", "https://budget.example/a b"])
        self.assertEqual((status, new), (200, []))


class LinkReserveTests(LowDiskFixture):
    free_bytes = GIB - 4096

    def test_no_link_is_stored_inside_the_1_gib_reserve(self):
        status, new = self.links(["https://reserve.example/a"])
        self.assertEqual((status, new), (507, []))
        self.assertIn("/Ask rejected: not enough free space while preserving 1073741824 bytes",
                      self.log.read_text())


if __name__ == "__main__":
    unittest.main()
