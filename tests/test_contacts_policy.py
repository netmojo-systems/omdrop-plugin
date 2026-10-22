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
import shutil
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
        self.mid_crt, self.mid_key = self.issue("mid", "Test Issuing CA",
                                                (self.root_crt, self.root_key), ca=True)
        # Records are signed by a record-signing certificate under it, as
        # Apple's are by AppleIDValidationRecordSigning05 under AAI2.
        self.signer = self.issue("signer", "AppleIDValidationRecordSigningTest",
                                 (self.mid_crt, self.mid_key))
        self._n = 0

    def issue(self, name, cn, issuer, ca=False):
        """A certificate for cn issued by issuer, a (certificate, key) pair."""
        key, crt, csr = (self.tmp / f"{name}.{ext}" for ext in ("key", "pem", "csr"))
        sh("openssl", "req", "-newkey", "rsa:2048", "-nodes",
           "-keyout", str(key), "-out", str(csr), "-subj", f"/O=Test/CN={cn}")
        ext = (b"basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\n"
               if ca else b"basicConstraints=critical,CA:FALSE\n")
        sh("openssl", "x509", "-req", "-in", str(csr), "-CA", str(issuer[0]),
           "-CAkey", str(issuer[1]), "-CAcreateserial", "-days", "2",
           "-out", str(crt), "-extfile", "/dev/stdin", input=ext)
        return crt, key

    def payload(self, identifiers, account, age_days=0, duration=30 * 86400, **extra):
        return plistlib.dumps({
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
            **extra,
        })

    def sign(self, payload, signers, chain):
        """A DER CMS record over payload from each (certificate, key) in
        signers, carrying the certificates in chain for openssl to build on."""
        src = self.tmp / "payload.bin"
        src.write_bytes(payload)
        bundle = self.tmp / "chain.pem"
        bundle.write_bytes(b"".join(Path(c).read_bytes() for c in chain))
        args = []
        for crt, key in signers:
            args += ["-signer", str(crt), "-inkey", str(key)]
        return sh("openssl", "cms", "-sign", "-in", str(src), *args,
                  *(["-certfile", str(bundle)] if chain else []),
                  "-outform", "DER", "-binary", "-nodetach").stdout

    def record(self, identifiers, account, age_days=0, duration=30 * 86400):
        return self.sign(self.payload(identifiers, account, age_days, duration),
                         [self.signer], [self.mid_crt])

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
        return contacts.decide(record, cert, known=known, ca_file=self.ca,
                               untrusted=self.mid, record_ca=self.mid[0])[0]

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
        # In the signed payload: a flip in the copy of the intermediate the
        # record carries changes nothing, as the trusted copy is used.
        record[record.index(self.ACCOUNT.encode())] ^= 0x01
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


class RecordSignatureTests(unittest.TestCase):
    """Only Apple's record-signing certificate speaks for an Apple ID.

    Apple Root CA issues to many Apple services. Trusting a record because it
    chains to that root accepts one signed by any of them; trusting the system
    CA store as well, which openssl does unless told not to, accepts one
    signed under any public CA. A record must chain to the AAI2 intermediate
    alone, and its one signer must be named AppleIDValidationRecordSigning...

    A real record-signing certificate can't be minted here, so the tests
    stand a throwaway root in for Apple Root CA and a throwaway intermediate
    in for AAI2, through the module paths verify_record defaults to.
    """

    ACCOUNT = "001288-10-AAAA-BBBB-CCCC-DDDD"

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        fx = cls.fx = Fixtures(cls._tmp.name)
        root = (fx.root_crt, fx.root_key)
        # Another CA under the same root: Apple's root has many.
        cls.other_ca = fx.issue("other", "Test Other Service CA", root, ca=True)
        cls.other_signer = fx.issue("other-signer", "AppleIDValidationRecordSigningTest",
                                    cls.other_ca)
        cls.mallory = fx.issue("mallory", "Mallory", (fx.mid_crt, fx.mid_key))

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def setUp(self):
        # The defaults verify_record uses, pointed at the stand-ins. Before
        # the pin, records were checked against APPLE_ROOT_CA.
        for name, path in (("APPLE_ROOT_CA", self.fx.root_crt), ("RECORD_CA", self.fx.mid_crt)):
            patcher = mock.patch.object(contacts, name, Path(path), create=True)
            patcher.start()
            self.addCleanup(patcher.stop)

    def payload(self, **extra):
        return self.fx.payload(["friend@example.com"], self.ACCOUNT, **extra)

    def test_a_record_signed_by_apples_record_signing_certificate_verifies(self):
        info = contacts.verify_record(self.fx.record(["friend@example.com"], self.ACCOUNT))
        self.assertIsNotNone(info)
        self.assertEqual(info["account"], self.ACCOUNT)
        self.assertIn(contacts.hash_identifier("friend@example.com"), info["hashes"])
        self.assertFalse(info["expired"])

    def test_a_record_under_the_root_but_not_the_pinned_intermediate_is_refused(self):
        record = self.fx.sign(self.payload(), [self.other_signer], [self.other_ca[0]])
        self.assertIsNone(contacts.verify_record(record))

    def test_a_signer_without_the_record_signing_name_is_refused(self):
        record = self.fx.sign(self.payload(), [self.mallory], [self.fx.mid_crt])
        self.assertIsNone(contacts.verify_record(record))

    def test_the_intermediate_itself_cannot_sign_a_record(self):
        record = self.fx.sign(self.payload(), [(self.fx.mid_crt, self.fx.mid_key)], [])
        self.assertIsNone(contacts.verify_record(record))

    def test_a_second_signer_is_refused(self):
        record = self.fx.sign(self.payload(), [self.fx.signer, self.mallory], [self.fx.mid_crt])
        self.assertIsNone(contacts.verify_record(record))

    def test_the_systems_certificate_authorities_are_not_trusted(self):
        # The stand-in root, installed as a system CA: openssl reads
        # SSL_CERT_DIR and SSL_CERT_FILE in place of /etc/ssl/certs.
        record = self.fx.sign(self.payload(), [self.other_signer], [self.other_ca[0]])
        with tempfile.TemporaryDirectory() as system:
            shutil.copy(self.fx.root_crt, system)
            sh("openssl", "rehash", system)
            env = {"SSL_CERT_DIR": system, "SSL_CERT_FILE": str(self.fx.root_crt)}
            with mock.patch.dict(os.environ, env):
                self.assertIsNone(contacts.verify_record(record, str(self.fx.mid_crt)))

    def test_the_signed_payload_is_decoded_under_safeplists_limits(self):
        nested = []
        for _ in range(40):
            nested = [nested]
        record = self.fx.sign(self.payload(Nested=nested), [self.fx.signer], [self.fx.mid_crt])
        self.assertIsNone(contacts.verify_record(record))

    def test_a_payload_that_is_not_a_dictionary_is_refused(self):
        record = self.fx.sign(plistlib.dumps(["not", "a", "record"]),
                              [self.fx.signer], [self.fx.mid_crt])
        self.assertIsNone(contacts.verify_record(record))

    def test_decide_refuses_a_record_under_another_ca_of_the_same_root(self):
        record = self.fx.sign(self.payload(), [self.other_signer], [self.other_ca[0]])
        known = {contacts.hash_identifier("friend@example.com")}
        outcome, _ = contacts.decide(record, b"unused", known=known)
        self.assertEqual(outcome, contacts.REJECT_BAD_RECORD)
        outcome, detail = contacts.decide_discovery(record, known=known)
        self.assertEqual((outcome, detail), (contacts.ACCEPT, {"identified": False}))


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

    def test_records_are_pinned_to_apples_aai2_intermediate(self):
        ca = contacts.record_ca()
        self.assertIsNotNone(ca)
        subject = subprocess.run(["openssl", "x509", "-in", ca, "-noout", "-subject",
                                  "-nameopt", "multiline"], capture_output=True, text=True).stdout
        self.assertRegex(subject, r"commonName\s*=\s*Apple Application Integration 2 "
                                  r"Certification Authority\n")


if __name__ == "__main__":
    unittest.main()
