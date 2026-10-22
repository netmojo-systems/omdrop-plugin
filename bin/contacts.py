"""Decide whether an AirDrop sender is someone this machine knows.

Apple's "Contacts Only" is not a name check. Every sender that proposes a
transfer presents two things, measured from real transfers on 2026-09-18:

  * an Apple-issued client certificate, on /Ask and /Upload but never on
    /Discover, with subject CN=com.apple.idms.appleid.prd.<altDsID> and an
    RSA-2048 key, issued by Apple Application Integration Certification
    Authority;
  * an Apple ID validation record: a CMS blob signed by Apple carrying the
    SHA-256 of every phone number and email address verified against that
    Apple ID, and the same altDsID.

So we can answer "do I know this person" with the evidence a Mac uses, and we
need nothing from Apple to do it: verifying their signatures requires only
Apple's public certificates, which this plugin ships in share/certs and
bin/apple-ca.

Three checks, and all three matter:

  1. the record is signed by Apple's record-signing certificate
     (CN=AppleIDValidationRecordSigning..), issued by the "Apple Application
     Integration 2 Certification Authority" -- otherwise anyone can assert
     any identifiers. Not merely by something under Apple Root CA: that
     root issues to many Apple services, and none of the others speaks for
     an Apple ID;
  2. the certificate is Apple-issued AND its CN ends with the record's
     altDsID -- otherwise a record harvested off the air by a passive prober
     can be replayed by someone who does not hold the matching key. Records
     are handed to any prober that asks, so this is not hypothetical;
  3. a hashed identifier in the record matches our address book.

What this deliberately does not do is trust SenderComputerName. It is chosen
by the sender: anybody can call their laptop anything.
"""

import hashlib
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import safeplist

CONFIG = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "omdrop"
KNOWN_SENDERS = CONFIG / "known-senders"
APPLE_ISSUER_CN = "Apple Application Integration Certification Authority"
CN_PREFIX = "com.apple.idms.appleid.prd."
APPLE_ROOT_CA = Path(__file__).resolve().parent.parent / "share" / "certs" / "apple_root_ca.pem"
# The one trust anchor for validation records: genuine records are signed by
# CN=AppleIDValidationRecordSigning05, issued by this intermediate.
RECORD_CA = Path(__file__).resolve().parent / "apple-ca" / "apple-aai2-ca.pem"
RECORD_SIGNER_CN_PREFIX = "AppleIDValidationRecordSigning"
# Only the certificates named on the command line: openssl otherwise adds
# the system's CA directory and store, and with them every public CA.
NO_SYSTEM_CAS = ["-no-CApath", "-no-CAstore"]

# Outcomes. The caller turns these into an HTTP answer and a log line; keeping
# them apart from the transport makes the policy testable on its own.
ACCEPT = "accept"
REJECT_NO_RECORD = "no-record"
REJECT_BAD_RECORD = "bad-record"
REJECT_NO_CERT = "no-certificate"
REJECT_UNBOUND = "record-not-bound-to-certificate"
REJECT_UNKNOWN = "not-a-known-sender"

WHY = {
    ACCEPT: "sender is a known contact",
    REJECT_NO_RECORD: "sender sent no Apple ID validation record",
    REJECT_BAD_RECORD: "the validation record is not signed by Apple, or has expired",
    REJECT_NO_CERT: "sender presented no client certificate",
    REJECT_UNBOUND: "the validation record does not belong to the presented certificate",
    REJECT_UNKNOWN: "sender is not in the known-senders list",
}


def apple_root_ca():
    """Apple's public root, shipped with this plugin. Public; no account needed."""
    return str(APPLE_ROOT_CA) if APPLE_ROOT_CA.is_file() else None


def record_ca():
    """The intermediate that issues Apple's record-signing certificate."""
    return str(RECORD_CA) if RECORD_CA.is_file() else None


def _subject_cn(pem):
    """The subject CN of one PEM certificate, "" if it has none.

    One attribute per line, "commonName = value". The default one-line
    subject is "CN = value" on OpenSSL 3.0 (Debian 12, Ubuntu 22.04 and
    24.04) and "CN=value" on later releases, so searching it for "CN="
    refused every Apple certificate on 3.0.
    """
    subject = subprocess.run(["openssl", "x509", "-noout", "-subject", "-nameopt", "multiline"],
                             input=pem, capture_output=True).stdout.decode(errors="replace")
    cn = ""
    for line in subject.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip() == "commonName":
            cn = value.strip()
    return cn


PEM_CERT = re.compile(rb"-----BEGIN CERTIFICATE-----\r?\n.*?-----END CERTIFICATE-----\r?\n?", re.S)


def normalize(entry):
    """Normalize an address-book entry the way AirDrop does before hashing.

    Phone numbers hash digits-only -- "+1 (234) 567-8901" hashes as
    "12345678901" -- and emails hash lowercased. Getting this wrong yields a
    silent non-match, which looks exactly like "not a contact", so it is worth
    being exact about.
    """
    entry = entry.strip()
    if not entry or entry.startswith("#"):
        return None
    if "@" in entry:
        return entry.lower()
    digits = re.sub(r"\D", "", entry)
    return digits or None


def hash_identifier(entry):
    return hashlib.sha256(entry.encode()).hexdigest().lower()


def known_hashes(path=None):
    """Hashed identifiers of everyone we accept from.

    The file holds identifiers in the clear because a user has to be able to
    read and edit it; hashing happens here, at comparison time.
    """
    path = Path(path or KNOWN_SENDERS)
    if not path.exists():
        return set()
    out = set()
    for line in path.read_text(errors="replace").splitlines():
        entry = normalize(line)
        if entry:
            out.add(hash_identifier(entry))
    return out


def verify_record(record, ca_file=None):
    """Apple's signature over the record, and what it says. None if invalid.

    ca_file is the one trust anchor, the AAI2 intermediate unless a test
    names its own; -partial_chain lets an intermediate be one, and the
    system's CAs are never consulted. The record must have exactly one
    signer, a record-signing certificate: Apple Root CA and the
    intermediate issue certificates for other Apple services too, and those
    say nothing about an Apple ID.

    -purpose any is required: the signer is a record-signing certificate, not
    an S/MIME one, so openssl's default purpose check rejects genuine records.
    """
    ca = ca_file or record_ca()
    if not ca or not record:
        return None
    with tempfile.TemporaryDirectory() as tmp:
        out, signers = Path(tmp) / "payload", Path(tmp) / "signers.pem"
        proc = subprocess.run(
            ["openssl", "cms", "-verify", "-inform", "DER", "-CAfile", ca, *NO_SYSTEM_CAS,
             "-partial_chain", "-purpose", "any", "-signer", str(signers), "-out", str(out)],
            input=record, capture_output=True)
        if proc.returncode != 0:
            return None
        # One signer, and it signs records: as in core.
        certs = PEM_CERT.findall(signers.read_bytes())
        if len(certs) != 1 or not _subject_cn(certs[0]).startswith(RECORD_SIGNER_CN_PREFIX):
            return None
        payload = out.read_bytes()
    # Decoded under the limits every plist from a peer gets, as in core: the
    # record arrives in a stranger's Ask, and the signature says who signed
    # it, not that its payload is small.
    try:
        plist = safeplist.loads(payload)
    except Exception:
        return None
    if not isinstance(plist, dict):
        return None

    valid_as_of = plist.get("ValidAsOf")
    duration = plist.get("SuggestValidDuration")
    expires = None
    if isinstance(valid_as_of, datetime) and isinstance(duration, (int, float)):
        base = valid_as_of if valid_as_of.tzinfo else valid_as_of.replace(tzinfo=timezone.utc)
        expires = base.timestamp() + duration
    hashes = {h.lower() for h in
              (plist.get("ValidatedEmailHashes") or []) + (plist.get("ValidatedPhoneHashes") or [])
              if isinstance(h, str)}
    return {
        "account": plist.get("altDsID", ""),
        "hashes": hashes,
        "expires": expires,
        "expired": bool(expires and expires < datetime.now(timezone.utc).timestamp()),
    }


def apple_intermediates():
    """Apple's public issuing CAs, vendored beside this file.

    Needed because a leaf alone cannot be verified: the sender presents only
    its own certificate, not the chain above it.
    """
    path = Path(__file__).resolve().parent / "apple-ca"
    return sorted(str(p) for p in path.glob("*.pem")) if path.is_dir() else []


def certificate_account(der, ca_file=None, untrusted=None):
    """The Apple ID a client certificate belongs to, or "" if it is not one.

    The certificate must actually verify to Apple's root. An earlier version of
    this checked only that the issuer *name* said Apple, which is worth naming
    as a mistake: a name is a string an attacker writes into their own
    self-signed certificate. Everyone-mode peers legitimately present an
    ephemeral self-signed certificate with CN=airdrop, and those yield "" here.
    """
    if not der:
        return ""
    ca = ca_file or apple_root_ca()
    if not ca:
        return ""          # fail closed: without the root we cannot judge
    chain = list(untrusted) if untrusted is not None else apple_intermediates()
    with tempfile.TemporaryDirectory() as tmp:
        leaf = Path(tmp) / "leaf.pem"
        pem = subprocess.run(["openssl", "x509", "-inform", "DER", "-out", str(leaf)],
                             input=der, capture_output=True)
        if pem.returncode != 0:
            return ""
        args = ["openssl", "verify", "-CAfile", ca, "-purpose", "any"]
        if chain:
            bundle = Path(tmp) / "chain.pem"
            bundle.write_bytes(b"".join(Path(c).read_bytes() for c in chain))
            args += ["-untrusted", str(bundle)]
        verified = subprocess.run([*args, str(leaf)], capture_output=True)
        if verified.returncode != 0:
            return ""
        # One attribute per line, "commonName = value". The default one-line
        # subject is "CN = value" on OpenSSL 3.0 (Debian 12, Ubuntu 22.04 and
        # 24.04) and "CN=value" on later releases, so searching it for "CN="
        # refused every Apple certificate on 3.0.
        subject = subprocess.run(["openssl", "x509", "-in", str(leaf), "-noout", "-subject",
                                  "-nameopt", "multiline"],
                                 capture_output=True).stdout.decode(errors="replace")
    cn = ""
    for line in subject.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip() == "commonName":
            cn = value.strip()
    return cn[len(CN_PREFIX):] if cn.startswith(CN_PREFIX) else ""


def decide(record, peer_cert, known=None, ca_file=None, untrusted=None, record_ca=None):
    """Should we accept a transfer from this sender? Returns (outcome, detail).

    `detail` carries no identifier: the hashes are reversible to a phone
    number by brute force, so they must not reach a log file. ca_file and
    untrusted are for the client certificate, record_ca for the record (see
    verify_record); a test names its own, a caller leaves them to Apple's.
    """
    known = known_hashes() if known is None else known
    if not record:
        return REJECT_NO_RECORD, {}
    info = verify_record(record, record_ca)
    if info is None or info["expired"]:
        return REJECT_BAD_RECORD, {"expired": bool(info and info["expired"])}
    if not peer_cert:
        return REJECT_NO_CERT, {}
    account = certificate_account(peer_cert, ca_file, untrusted)
    if not account or account != info["account"]:
        return REJECT_UNBOUND, {"apple_issued_certificate": bool(account)}
    if not known:
        return REJECT_UNKNOWN, {"known_senders": 0}
    if info["hashes"] & known:
        return ACCEPT, {"known_senders": len(known)}
    return REJECT_UNKNOWN, {"known_senders": len(known)}


def decide_discovery(record, known=None, record_ca=None):
    """May this sender even see us? Returns (outcome, detail).

    DELIBERATELY WEAKER THAN `decide`, and usable only for discovery.

    A sender presents its Apple-issued client certificate on /Ask and never on
    /Discover (measured 2026-09-18), so at discovery time there is nothing to
    bind the record to the live connection: anyone who can replay a known
    contact's record can be answered. That is spoofable and must never gate a
    transfer. `decide` stays the only thing that does.

    What it is good for is not appearing in a stranger's share sheet, which is
    what Apple's Contacts Only does and what this mode's name implies.

    FAILS OPEN, and the direction matters: we hide only from a sender we have
    positively identified as not being a contact. A missing, malformed or
    expired record returns ACCEPT, because "we could not tell who this is" must
    not become "hide from a device we have never measured" -- an iPhone that
    omits the record would otherwise stop seeing this machine entirely. The
    /Ask gate still refuses the transfer either way.
    """
    known = known_hashes() if known is None else known
    if not record:
        return ACCEPT, {"identified": False}
    info = verify_record(record, record_ca)
    if info is None or info["expired"]:
        return ACCEPT, {"identified": False}
    if known and info["hashes"] & known:
        return ACCEPT, {"identified": True}
    return REJECT_UNKNOWN, {"known_senders": len(known)}


def visibility(path=None):
    """`everyone` (default) or `contacts`. Absent file means everyone, because
    a machine that silently refuses everybody is worse than one that asks."""
    path = Path(path) if path else CONFIG / "visibility"
    try:
        value = path.read_text().strip().lower()
    except OSError:
        return "everyone"
    return "contacts" if value == "contacts" else "everyone"
