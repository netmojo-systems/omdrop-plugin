"""What a nearby device sends cannot reach the log, or the disk, unbounded.

Anything in range can send to the receiver in Everyone mode, so every name,
header and link it carries is untrusted. These tests hold the Python receiver
to the rules omdrop-core follows for the same input: log lines escaped and
capped as core's log::escape() does them, and links checked and budgeted
before anything is written.
"""

import logging
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


if __name__ == "__main__":
    unittest.main()
