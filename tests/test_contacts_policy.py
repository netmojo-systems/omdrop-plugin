"""Contacts Only accepts the people you know and nobody else.

The interesting cases are the refusals. A validation record is handed to any
prober that asks, so the one that matters most is a *valid* record replayed by
someone who does not hold the matching Apple-issued key: that must fail, or
"Contacts Only" means nothing.

Records are signed by Apple and cannot be minted here, so these tests build a
throwaway CA and sign their own, exercising the real openssl CMS path rather
than a stubbed one.
"""

import os
import plistlib
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "bin"))
import contacts  # noqa: E402



def sh(*args, **kw):
    return subprocess.run(args, capture_output=True, check=True, **kw)


class Fixtures:
    """A stand-in for Apple: a root, an issuing CA under it, and signed material.

    The certificates really chain, because the policy really verifies the
    chain; a fixture that only *names* an issuer would pass a check that no
    longer exists.
    """

    def __init__(self, tmp):
        self.tmp = Path(tmp)
        self.root_key, self.root_crt = self.tmp / "root.key", self.tmp / "root.pem"
        sh("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
           "-keyout", str(self.root_key), "-out", str(self.root_crt), "-days", "2",
           "-subj", "/O=Test/CN=Test Root CA")
        # An intermediate, mirroring Apple: leaves are issued below the root.
        self.mid_key, self.mid_crt = self.tmp / "mid.key", self.tmp / "mid.pem"
        csr = self.tmp / "mid.csr"
        sh("openssl", "req", "-newkey", "rsa:2048", "-nodes",
           "-keyout", str(self.mid_key), "-out", str(csr), "-subj", "/O=Test/CN=Test Issuing CA")
        sh("openssl", "x509", "-req", "-in", str(csr), "-CA", str(self.root_crt),
           "-CAkey", str(self.root_key), "-CAcreateserial", "-days", "2",
           "-out", str(self.mid_crt), "-extfile", "/dev/stdin",
           input=b"basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\n")
        self._n = 0

    def record(self, identifiers, account, age_days=0, duration=30 * 86400):
        payload = plistlib.dumps({
            "Version": 2,
            "altDsID": account,
            "encDsID": account,
            "ValidAsOf": datetime.now(timezone.utc) - timedelta(days=age_days),
            "SuggestValidDuration": duration,
            # Apple stores already-normalized hashes: emails lowercased, phones
            # digits-only. Mirror that, or a match would test nothing real.
            "ValidatedEmailHashes": [contacts.hash_identifier(contacts.normalize(i))
                                     for i in identifiers if "@" in i],
            "ValidatedPhoneHashes": [contacts.hash_identifier(contacts.normalize(i))
                                     for i in identifiers if "@" not in i],
        })
        src = self.tmp / "payload.bin"
        src.write_bytes(payload)
        return sh("openssl", "cms", "-sign", "-in", str(src), "-signer", str(self.mid_crt),
                  "-inkey", str(self.mid_key), "-outform", "DER", "-binary",
                  "-nodetach").stdout

    def certificate(self, account, issued_by_ca=True):
        """A client certificate: issued under the test root, or self-signed.

        Self-signed stands for two real cases at once -- the ephemeral
        CN=airdrop certificate an Everyone-mode peer presents, and an impostor
        who writes Apple's name into their own issuer field.
        """
        self._n += 1
        key = self.tmp / f"c{self._n}.key"
        crt = self.tmp / f"c{self._n}.pem"
        csr = self.tmp / f"c{self._n}.csr"
        cn = f"{contacts.CN_PREFIX}{account}" if account else "airdrop"
        sh("openssl", "req", "-newkey", "rsa:2048", "-nodes",
           "-keyout", str(key), "-out", str(csr), "-subj", f"/O=Apple Inc./CN={cn}")
        if issued_by_ca:
            sh("openssl", "x509", "-req", "-in", str(csr), "-CA", str(self.mid_crt),
               "-CAkey", str(self.mid_key), "-CAcreateserial", "-days", "2", "-out", str(crt))
        else:
            sh("openssl", "x509", "-req", "-in", str(csr), "-signkey", str(key),
               "-days", "2", "-out", str(crt))
        return sh("openssl", "x509", "-in", str(crt), "-outform", "DER").stdout

class ContactsPolicyTests(unittest.TestCase):
    # Real altDsID is 46 chars, but `openssl req` caps a CN at 64 and the
    # prefix eats 27, so these synthetic accounts are shorter. The binding
    # logic is length-independent; the real 73-char CN is covered by the
    # captured-certificate evidence, not here.
    ACCOUNT = "001288-10-AAAA-BBBB-CCCC-DDDD"
    OTHER = "001288-10-FFFF-9999-8888-7777"

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.fx = Fixtures(cls._tmp.name)
        cls.ca = str(cls.fx.root_crt)
        cls.mid = [str(cls.fx.mid_crt)]

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def decide(self, record, cert, known):
        return contacts.decide(record, cert, known=known,
                               ca_file=self.ca, untrusted=self.mid)[0]

    # -- the identifier matching a user actually experiences -----------------

    def test_phone_matches_however_the_user_typed_it(self):
        record = self.fx.record(["+1 (555) 010-9999"], self.ACCOUNT)
        cert = self.fx.certificate(self.ACCOUNT)
        for written in ("+1 555 010 9999", "15550109999", "+1-555-010-9999"):
            known = {contacts.hash_identifier(contacts.normalize(written))}
            self.assertEqual(contacts.ACCEPT, self.decide(record, cert, known), written)

    def test_email_matches_regardless_of_case(self):
        record = self.fx.record(["Someone@Example.com"], self.ACCOUNT)
        cert = self.fx.certificate(self.ACCOUNT)
        known = {contacts.hash_identifier("someone@example.com")}
        self.assertEqual(contacts.ACCEPT, self.decide(record, cert, known))

    def test_a_stranger_is_refused(self):
        record = self.fx.record(["stranger@example.com"], self.ACCOUNT)
        cert = self.fx.certificate(self.ACCOUNT)
        known = {contacts.hash_identifier("friend@example.com")}
        self.assertEqual(contacts.REJECT_UNKNOWN, self.decide(record, cert, known))

    def test_one_matching_identifier_is_enough(self):
        record = self.fx.record(["a@example.com", "b@example.com", "5550001111"], self.ACCOUNT)
        cert = self.fx.certificate(self.ACCOUNT)
        known = {contacts.hash_identifier("b@example.com")}
        self.assertEqual(contacts.ACCEPT, self.decide(record, cert, known))

    # -- the refusals that make the feature mean something -------------------

    def test_valid_record_replayed_without_the_key_is_refused(self):
        """The attack the binding exists to stop: records are public.

        A prober collects a genuine record off the air, then presents it with
        its own certificate. Every signature checks out; the account does not.
        """
        record = self.fx.record(["friend@example.com"], self.ACCOUNT)
        impostor = self.fx.certificate(self.OTHER)
        known = {contacts.hash_identifier("friend@example.com")}
        self.assertEqual(contacts.REJECT_UNBOUND, self.decide(record, impostor, known))

    def test_account_is_read_whatever_subject_format_openssl_prints(self):
        """OpenSSL 3.0 (Debian 12, Ubuntu 22.04 and 24.04) prints a one-line
        subject as "O = Apple Inc., CN = value"; later releases print
        "CN=value". Reading the account by searching for "CN=" refused every
        Apple-issued certificate on 3.0, as "the validation record does not
        belong to the presented certificate". Any `openssl x509 -subject`
        here that names no format gets 3.0's (-nameopt oneline), so this
        holds whichever OpenSSL the machine has.
        """
        real_run = subprocess.run

        def as_openssl_3_0(args, *a, **kw):
            args = list(args)
            if args[:2] == ["openssl", "x509"] and "-subject" in args and "-nameopt" not in args:
                args += ["-nameopt", "oneline"]
            return real_run(args, *a, **kw)

        cert = self.fx.certificate(self.ACCOUNT)
        with mock.patch.object(contacts.subprocess, "run", as_openssl_3_0):
            account = contacts.certificate_account(cert, self.ca, self.mid)
        self.assertEqual(self.ACCOUNT, account)

    def test_self_signed_certificate_cannot_carry_an_account(self):
        """Everyone-mode peers present an ephemeral self-signed certificate."""
        record = self.fx.record(["friend@example.com"], self.ACCOUNT)
        ephemeral = self.fx.certificate("", issued_by_ca=False)
        known = {contacts.hash_identifier("friend@example.com")}
        self.assertEqual(contacts.REJECT_UNBOUND, self.decide(record, ephemeral, known))

    def test_unsigned_claims_are_refused(self):
        """A plist someone wrote themselves, with the right shape and no signature."""
        forged = plistlib.dumps({"altDsID": self.ACCOUNT,
                                 "ValidatedEmailHashes":
                                     [contacts.hash_identifier("friend@example.com")]})
        cert = self.fx.certificate(self.ACCOUNT)
        known = {contacts.hash_identifier("friend@example.com")}
        self.assertEqual(contacts.REJECT_BAD_RECORD, self.decide(forged, cert, known))

    def test_a_tampered_record_is_refused(self):
        record = bytearray(self.fx.record(["friend@example.com"], self.ACCOUNT))
        record[len(record) // 2] ^= 0x01
        cert = self.fx.certificate(self.ACCOUNT)
        known = {contacts.hash_identifier("friend@example.com")}
        self.assertEqual(contacts.REJECT_BAD_RECORD, self.decide(bytes(record), cert, known))

    def test_an_expired_record_is_refused(self):
        record = self.fx.record(["friend@example.com"], self.ACCOUNT,
                                age_days=60, duration=30 * 86400)
        cert = self.fx.certificate(self.ACCOUNT)
        known = {contacts.hash_identifier("friend@example.com")}
        self.assertEqual(contacts.REJECT_BAD_RECORD, self.decide(record, cert, known))

    def test_no_certificate_is_refused_even_with_a_good_record(self):
        record = self.fx.record(["friend@example.com"], self.ACCOUNT)
        known = {contacts.hash_identifier("friend@example.com")}
        self.assertEqual(contacts.REJECT_NO_CERT, self.decide(record, None, known))

    def test_no_record_is_refused(self):
        cert = self.fx.certificate(self.ACCOUNT)
        known = {contacts.hash_identifier("friend@example.com")}
        self.assertEqual(contacts.REJECT_NO_RECORD, self.decide(None, cert, known))

    def test_empty_known_senders_refuses_everyone(self):
        """An empty list must not mean "accept anybody"."""
        record = self.fx.record(["friend@example.com"], self.ACCOUNT)
        cert = self.fx.certificate(self.ACCOUNT)
        self.assertEqual(contacts.REJECT_UNKNOWN, self.decide(record, cert, set()))

    # -- the mode switch -----------------------------------------------------

    def test_visibility_defaults_to_everyone_when_unset(self):
        """A machine that silently refuses everyone is worse than one that asks."""
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual("everyone", contacts.visibility(Path(d) / "absent"))

    def test_visibility_reads_contacts(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "visibility"
            path.write_text("contacts\n")
            self.assertEqual("contacts", contacts.visibility(path))
            path.write_text("garbage\n")
            self.assertEqual("everyone", contacts.visibility(path))

    # -- the address book file ----------------------------------------------

    def test_known_senders_file_ignores_comments_and_blanks(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "known-senders"
            path.write_text("# my people\n\nFriend@Example.com\n+1 (555) 010-9999\n")
            hashes = contacts.known_hashes(path)
            self.assertEqual(2, len(hashes))
            self.assertIn(contacts.hash_identifier("friend@example.com"), hashes)
            self.assertIn(contacts.hash_identifier("15550109999"), hashes)


class VendoredAppleCATests(unittest.TestCase):
    """The CAs shipped beside contacts.py keep verifying Apple senders.

    Apple's first Application Integration CA, as first vendored, expired on
    2026-10-21. Apple re-issued it with the same name and key, valid until
    2028-10-04, and iPhones send that copy. A receiver that trusts the expired
    copy picks it over the one in the handshake, and from then refuses every
    Contacts Only sender whose certificate it issued (#75).
    """

    AFTER_THE_OLD_EXPIRY = 1792627200  # 2026-10-22T00:00:00Z

    def test_every_vendored_intermediate_chains_to_the_root_after_2026_10_21(self):
        root = contacts.apple_root_ca()
        self.assertIsNotNone(root)
        intermediates = contacts.apple_intermediates()
        self.assertTrue(intermediates)
        for pem in intermediates:
            with self.subTest(pem=Path(pem).name):
                verified = subprocess.run(
                    ["openssl", "verify", "-attime", str(self.AFTER_THE_OLD_EXPIRY),
                     "-CAfile", root, pem], capture_output=True, text=True)
                self.assertEqual(0, verified.returncode, verified.stdout + verified.stderr)


if __name__ == "__main__":
    unittest.main()
