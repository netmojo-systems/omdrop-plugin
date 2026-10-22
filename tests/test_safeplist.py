"""Peer property lists are refused when their references expand past the
limits omdrop-core's safeplist.rs applies."""

import plistlib
import struct
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "bin"))
import safeplist  # noqa: E402


def binary(value):
    # plistlib's writer stores an object once however often it is referenced,
    # which is exactly the shape a hostile sender would hand-build.
    return plistlib.dumps(value, fmt=plistlib.FMT_BINARY)


def many_ids(members=200_000, ids=1000):
    """One array of `members` references, given `ids` object IDs, and a root
    array naming every one of those IDs: about 400 KB."""
    count = ids + 3
    body = bytearray(b"bplist00")
    offsets = [len(body)]
    body += b"\x10\x01"                      # object 0: the integer 1
    array_at = len(body)
    body += b"\xaf\x12" + struct.pack(">I", members) + struct.pack(">H", 0) * members
    offsets += [array_at] * (ids + 1)        # objects 1..ids+1: that array
    offsets.append(len(body))
    body += b"\xaf\x12" + struct.pack(">I", ids)
    body += b"".join(struct.pack(">H", i) for i in range(2, ids + 2))
    table = len(body)
    body += b"".join(struct.pack(">I", o) for o in offsets)
    body += bytes(6) + bytes([4, 2]) + struct.pack(">QQQ", count, count - 1, table)
    return bytes(body)


class SafePlistTests(unittest.TestCase):
    def test_an_ordinary_ask_decodes(self):
        ask = {"SenderComputerName": "Mac", "TransferType": {"files": 1}, "Items": [],
               "SenderRecordData": b"\x01\x02\x03",
               "Files": [{"FileName": f"{i}.jpg", "FileType": "public.jpeg", "FileSize": i}
                         for i in range(512)]}
        self.assertEqual(safeplist.loads(binary(ask)), ask)
        self.assertEqual(safeplist.loads(plistlib.dumps(ask, fmt=plistlib.FMT_XML)), ask)
        with self.assertRaises(plistlib.InvalidFileException):
            safeplist.loads(b"not a plist")

    def test_shared_references_cannot_expand_exponentially(self):
        # Five levels of 200 references to the level below: about 1 KB
        # describing 200^4 = 1.6 billion values.
        value = []
        for _ in range(4):
            value = [value] * 200
        body = binary(value)
        self.assertLess(len(body), 1024)
        with self.assertRaises(safeplist.TooComplex):
            safeplist.loads(body)
        # One level of the same shape is fine.
        self.assertEqual(len(safeplist.loads(binary([[]] * 200))), 200)

    def test_one_large_entry_named_many_times_is_refused_quickly(self):
        # The /Ask from omacom/omarchy-plugin-marketplace#10665: under 1 MiB on
        # the wire, 54 GB once its file names are listed.
        entry = {"FileName": "A" * 60_000, "FileType": "public.data", "FileSize": 1}
        bomb = binary({"Files": [entry] * 900_000})
        self.assertLess(len(bomb), 1 << 20)
        started = time.monotonic()
        with self.assertRaises(safeplist.TooComplex):
            safeplist.loads(bomb)
        self.assertLess(time.monotonic() - started, 5)
        # A few references to the same entry are within budget.
        self.assertEqual(len(safeplist.loads(binary({"Files": [entry] * 3}))["Files"]), 3)

    def test_shared_data_cannot_expand_past_the_byte_budget(self):
        data = b"A" * 840_000
        with self.assertRaises(safeplist.TooComplex):
            safeplist.loads(binary([data] * 199_000))
        self.assertEqual(len(safeplist.loads(binary([data] * 3))), 3)

    def test_deep_nesting_and_cycles_are_refused(self):
        depth = 200_000
        xml = ('<?xml version="1.0"?><plist version="1.0">' + "<array>" * depth
               + "</array>" * depth + "</plist>").encode()
        with self.assertRaises(safeplist.TooComplex):
            safeplist.loads(xml)
        cycle = []
        cycle.append(cycle)
        with self.assertRaises(safeplist.TooComplex):
            safeplist.loads(binary(cycle))
        nested = []
        for _ in range(safeplist.MAX_DEPTH - 1):
            nested = [nested]
        safeplist.loads(binary(nested))
        with self.assertRaises(safeplist.TooComplex):
            safeplist.loads(binary([nested]))

    def test_one_array_under_many_ids_is_refused_while_decoding(self):
        # plistlib builds the array once per ID: 1000 lists, 1.6 GB, before
        # anything could measure the result.
        bomb = many_ids()
        self.assertLess(len(bomb), 1 << 20)
        started = time.monotonic()
        with self.assertRaises(safeplist.TooComplex):
            safeplist.loads(bomb)
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(len(safeplist.loads(many_ids(members=1000, ids=2))), 2)

    def test_a_count_larger_than_the_input_is_refused(self):
        # An array claiming 2**40 members, in a 50-byte body.
        body = bytearray(b"bplist00")
        body += b"\xaf\x13" + struct.pack(">Q", 1 << 40)
        table = len(body)
        body += bytes([8]) + bytes(6) + bytes([1, 1]) + struct.pack(">QQQ", 1, 0, table)
        with self.assertRaises(plistlib.InvalidFileException):
            safeplist.loads(bytes(body))


if __name__ == "__main__":
    unittest.main()
