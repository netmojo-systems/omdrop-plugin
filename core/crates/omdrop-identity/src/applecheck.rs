//! Apple's signature over a validation record, and whether a certificate
//! chains to Apple. Ported from omdrop-plugin's `contacts.py`; `openssl`
//! does the cryptography exactly as there (replacing the CMS check with a
//! pure-Rust one is security-relevant and needs captured Apple records to
//! prove), with the vendored PEMs written to private temporary files because
//! it needs paths.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::apple::Record;
use crate::keys::openssl;

/// The subject prefix of an Apple-issued AirDrop client certificate.
const CN_PREFIX: &str = "com.apple.idms.appleid.prd.";
/// The subject prefix of the certificate Apple signs validation records
/// with: `AppleIDValidationRecordSigning05` in 2026.
const RECORD_SIGNER_CN_PREFIX: &str = "AppleIDValidationRecordSigning";
const PEM_BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";

fn write_file(path: &Path, data: &[u8]) -> Option<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .ok()?;
    f.write_all(data).ok()
}

/// A private (0700) temporary directory holding the root CA as `ca.pem`.
fn workdir(root_pem: &[u8]) -> Option<tempfile::TempDir> {
    let dir = tempfile::Builder::new()
        .prefix("omdrop-apple.")
        .tempdir()
        .ok()?;
    write_file(&dir.path().join("ca.pem"), root_pem)?;
    Some(dir)
}

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Read a validation record's property list, once its signature verified.
/// Parsed under safeplist's limits all the same: a sender chooses the record
/// it presents, and the signature only says which certificate signed it.
pub(crate) fn record_from_plist(payload: &[u8], now: f64) -> Option<Record> {
    let value = crate::safeplist::parse(payload).ok()?;
    let dict = value.as_dictionary()?;
    let valid_as_of = dict.get("ValidAsOf").and_then(|v| v.as_date());
    // Python's isinstance(duration, (int, float)) also admits booleans.
    let duration = match dict.get("SuggestValidDuration") {
        Some(plist::Value::Integer(i)) => i
            .as_signed()
            .map(|n| n as f64)
            .or(i.as_unsigned().map(|n| n as f64)),
        Some(plist::Value::Real(r)) => Some(*r),
        Some(plist::Value::Boolean(b)) => Some(f64::from(u8::from(*b))),
        _ => None,
    };
    let expires = match (valid_as_of, duration) {
        (Some(date), Some(d)) => {
            let t = SystemTime::from(date);
            let base = match t.duration_since(UNIX_EPOCH) {
                Ok(after) => after.as_secs_f64(),
                Err(before) => -before.duration().as_secs_f64(),
            };
            Some(base + d)
        }
        _ => None,
    };
    let mut hashes = BTreeSet::new();
    for key in ["ValidatedEmailHashes", "ValidatedPhoneHashes"] {
        if let Some(list) = dict.get(key).and_then(|v| v.as_array()) {
            hashes.extend(
                list.iter()
                    .filter_map(|h| h.as_string())
                    .map(str::to_lowercase),
            );
        }
    }
    Some(Record {
        account: dict
            .get("altDsID")
            .and_then(|v| v.as_string())
            .unwrap_or("")
            .to_owned(),
        hashes,
        expires,
        // bool(expires and expires < now): an expiry of exactly 0 never expires.
        expired: matches!(expires, Some(e) if e != 0.0 && e < now),
    })
}

/// `openssl cms -verify` with `anchor_pem` as the only trusted certificate,
/// then the record's contents.
///
/// The anchor is the CA that issues Apple's record-signing certificates (in
/// production the vendored Application Integration 2 intermediate), trusted
/// on its own with `-partial_chain`, and the one signer's common name must
/// start with [`RECORD_SIGNER_CN_PREFIX`]. Anchoring at Apple's root accepted
/// a record signed by any certificate Apple issues, and an Apple ID's own
/// AirDrop certificate is one: its holder could sign a record claiming
/// anyone's email and phone hashes.
///
/// `-no-CApath -no-CAstore`: `-CAfile` adds to openssl's default trust store
/// rather than replacing it, so without them every CA in `/etc/ssl/certs`
/// (or `SSL_CERT_DIR`) could anchor a record's signer.
///
/// `-purpose any` is required: the signer is a record-signing certificate,
/// not an S/MIME one, so openssl's default purpose check rejects genuine
/// records.
pub(crate) fn verify_record_with(record: &[u8], anchor_pem: &[u8]) -> Option<Record> {
    if record.is_empty() || anchor_pem.is_empty() {
        return None;
    }
    let dir = workdir(anchor_pem)?;
    let ca = dir.path().join("ca.pem");
    let out = dir.path().join("out.bin");
    let signer = dir.path().join("signer.pem");
    let run = openssl(
        &[
            "cms".as_ref(),
            "-verify".as_ref(),
            "-inform".as_ref(),
            "DER".as_ref(),
            "-CAfile".as_ref(),
            ca.as_os_str(),
            "-no-CApath".as_ref(),
            "-no-CAstore".as_ref(),
            "-partial_chain".as_ref(),
            "-purpose".as_ref(),
            "any".as_ref(),
            "-signer".as_ref(),
            signer.as_os_str(),
            "-out".as_ref(),
            out.as_os_str(),
        ],
        Some(record),
        None,
        None,
    )
    .ok()?;
    if !run.status.success() {
        return None;
    }
    // Exactly one signer: openssl writes every verified signer's certificate.
    let signers = fs::read(&signer).ok()?;
    if signers
        .windows(PEM_BEGIN.len())
        .filter(|w| *w == PEM_BEGIN)
        .count()
        != 1
    {
        return None;
    }
    let subject = openssl(
        &[
            "x509".as_ref(),
            "-in".as_ref(),
            signer.as_os_str(),
            "-noout".as_ref(),
            "-subject".as_ref(),
            "-nameopt".as_ref(),
            "multiline".as_ref(),
        ],
        None,
        None,
        None,
    )
    .ok()?;
    if !subject.status.success()
        || !common_name(&String::from_utf8_lossy(&subject.stdout))
            .starts_with(RECORD_SIGNER_CN_PREFIX)
    {
        return None;
    }
    let payload = fs::read(&out).ok()?;
    record_from_plist(&payload, now_secs())
}

/// The `commonName = value` line of `openssl x509 -subject -nameopt
/// multiline` output (the last, as the plugin's contacts.py reads it). The
/// one-line default is `CN = value` on OpenSSL 3.0 (Debian 12, Ubuntu 22.04
/// and 24.04) and `CN=value` later, so searching it for `CN=` refused every
/// Apple certificate on 3.0 (plugin #67).
fn common_name(subject: &str) -> &str {
    let mut cn = "";
    for line in subject.lines() {
        if let Some((key, value)) = line.split_once('=')
            && key.trim() == "commonName"
        {
            cn = value.trim();
        }
    }
    cn
}

/// The account a certificate subject names, if its common name carries
/// Apple's AirDrop prefix.
fn account_from_subject(subject: &str) -> String {
    common_name(subject)
        .strip_prefix(CN_PREFIX)
        .unwrap_or("")
        .to_owned()
}

/// The Apple account a DER client certificate belongs to, or `""`.
///
/// The certificate must actually verify to `root_pem` through
/// `intermediates` (a sender presents only its leaf). Never a name check: an
/// earlier version checked only that the issuer name said Apple, and a name
/// is a string an attacker writes into their own self-signed certificate.
/// Everyone-mode peers present a self-signed `CN=airdrop`; those yield "".
/// openssl's default trust store is left out, as for records.
pub(crate) fn certificate_account_with(
    der: &[u8],
    root_pem: &[u8],
    intermediates: &[&[u8]],
) -> String {
    (|| {
        if der.is_empty() || root_pem.is_empty() {
            return None;
        }
        let dir = workdir(root_pem)?;
        let ca = dir.path().join("ca.pem");
        let leaf = dir.path().join("leaf.pem");
        let pem = openssl(
            &[
                "x509".as_ref(),
                "-inform".as_ref(),
                "DER".as_ref(),
                "-out".as_ref(),
                leaf.as_os_str(),
            ],
            Some(der),
            None,
            None,
        )
        .ok()?;
        if !pem.status.success() {
            return None;
        }
        let mut args = vec![
            "verify".as_ref(),
            "-CAfile".as_ref(),
            ca.as_os_str(),
            "-no-CApath".as_ref(),
            "-no-CAstore".as_ref(),
            "-purpose".as_ref(),
            "any".as_ref(),
        ];
        let bundle = dir.path().join("chain.pem");
        if !intermediates.is_empty() {
            write_file(&bundle, &intermediates.concat())?;
            args.push("-untrusted".as_ref());
            args.push(bundle.as_os_str());
        }
        args.push(leaf.as_os_str());
        if !openssl(&args, None, None, None).ok()?.status.success() {
            return None;
        }
        let subject = openssl(
            &[
                "x509".as_ref(),
                "-in".as_ref(),
                leaf.as_os_str(),
                "-noout".as_ref(),
                "-subject".as_ref(),
                "-nameopt".as_ref(),
                "multiline".as_ref(),
            ],
            None,
            None,
            None,
        )
        .ok()?;
        Some(account_from_subject(&String::from_utf8_lossy(
            &subject.stdout,
        )))
    })()
    .unwrap_or_default()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn run(dir: &Path, args: &[&str]) {
        let out = openssl(args, None, Some(dir), None).expect("openssl runs");
        assert!(
            out.status.success(),
            "openssl {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// A synthetic CA hierarchy standing in for Apple's: root -> intermediate
    /// -> leaf `CN=com.apple.idms.appleid.prd.<account>`, plus a record signer
    /// `CN=AppleIDValidationRecordSigning05` under the same intermediate.
    pub(crate) struct FakeApple {
        pub dir: tempfile::TempDir,
    }

    impl FakeApple {
        pub(crate) fn new() -> FakeApple {
            let dir = tempfile::tempdir().expect("tempdir");
            let d = dir.path();
            fs::write(
                d.join("ca.ext"),
                "basicConstraints=critical,CA:TRUE\nkeyUsage=keyCertSign,cRLSign\n",
            )
            .expect("ext");
            run(
                d,
                &[
                    "req",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-x509",
                    "-days",
                    "2",
                    "-subj",
                    "/CN=Fake Root",
                    "-addext",
                    "basicConstraints=critical,CA:TRUE",
                    "-addext",
                    "keyUsage=keyCertSign,cRLSign",
                    "-keyout",
                    "root.key",
                    "-out",
                    "root.pem",
                ],
            );
            let apple = FakeApple { dir };
            apple.intermediate_named("int", "Fake Intermediate");
            apple
        }

        /// Another intermediate `stem` under the same root.
        pub(crate) fn intermediate_named(&self, stem: &str, cn: &str) -> Vec<u8> {
            let d = self.dir.path();
            let (key, csr, pem) = (
                format!("{stem}.key"),
                format!("{stem}.csr"),
                format!("{stem}.pem"),
            );
            run(
                d,
                &[
                    "req",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-subj",
                    &format!("/CN={cn}"),
                    "-keyout",
                    &key,
                    "-out",
                    &csr,
                ],
            );
            run(
                d,
                &[
                    "x509",
                    "-req",
                    "-in",
                    &csr,
                    "-CA",
                    "root.pem",
                    "-CAkey",
                    "root.key",
                    "-CAcreateserial",
                    "-days",
                    "2",
                    "-extfile",
                    "ca.ext",
                    "-out",
                    &pem,
                ],
            );
            fs::read(d.join(&pem)).expect("intermediate")
        }

        pub(crate) fn path(&self, name: &str) -> std::path::PathBuf {
            self.dir.path().join(name)
        }

        pub(crate) fn root(&self) -> Vec<u8> {
            fs::read(self.path("root.pem")).expect("root")
        }

        pub(crate) fn intermediate(&self) -> Vec<u8> {
            fs::read(self.path("int.pem")).expect("int")
        }

        /// A leaf issued by the intermediate: (certificate PEM, key PEM).
        pub(crate) fn leaf(&self, name: &str, cn: &str) -> (Vec<u8>, Vec<u8>) {
            self.leaf_of("int", name, cn)
        }

        /// A leaf issued by intermediate `issuer`.
        pub(crate) fn leaf_of(&self, issuer: &str, name: &str, cn: &str) -> (Vec<u8>, Vec<u8>) {
            let d = self.dir.path();
            let (key, csr, pem) = (
                format!("{name}.key"),
                format!("{name}.csr"),
                format!("{name}.pem"),
            );
            let (ca, ca_key) = (format!("{issuer}.pem"), format!("{issuer}.key"));
            run(
                d,
                &[
                    "req",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-subj",
                    &format!("/CN={cn}"),
                    "-keyout",
                    &key,
                    "-out",
                    &csr,
                ],
            );
            run(
                d,
                &[
                    "x509",
                    "-req",
                    "-in",
                    &csr,
                    "-CA",
                    &ca,
                    "-CAkey",
                    &ca_key,
                    "-CAcreateserial",
                    "-days",
                    "2",
                    "-out",
                    &pem,
                ],
            );
            (
                fs::read(d.join(&pem)).expect("leaf"),
                fs::read(d.join(&key)).expect("key"),
            )
        }

        /// A DER CMS record over `plist`, signed as Apple signs one: by
        /// `CN=AppleIDValidationRecordSigning05`, issued by the intermediate,
        /// with the intermediate and root in the record's certificates.
        pub(crate) fn record(&self, plist_xml: &str) -> Vec<u8> {
            self.record_signed_by(
                "int",
                "signer",
                "AppleIDValidationRecordSigning05",
                plist_xml,
            )
        }

        /// A DER CMS record over `plist`, signed by leaf `name` (made once,
        /// named `cn`) of intermediate `issuer`.
        pub(crate) fn record_signed_by(
            &self,
            issuer: &str,
            name: &str,
            cn: &str,
            plist_xml: &str,
        ) -> Vec<u8> {
            let d = self.dir.path();
            if !d.join(format!("{name}.pem")).exists() {
                self.leaf_of(issuer, name, cn);
            }
            let mut chain = fs::read(d.join(format!("{issuer}.pem"))).expect("issuer");
            chain.extend(self.root());
            fs::write(d.join("chain.pem"), chain).expect("chain");
            fs::write(d.join("record.plist"), plist_xml).expect("plist");
            run(
                d,
                &[
                    "cms",
                    "-sign",
                    "-binary",
                    "-nodetach",
                    "-outform",
                    "DER",
                    "-in",
                    "record.plist",
                    "-signer",
                    &format!("{name}.pem"),
                    "-inkey",
                    &format!("{name}.key"),
                    "-certfile",
                    "chain.pem",
                    "-out",
                    "record.cms",
                ],
            );
            fs::read(d.join("record.cms")).expect("record")
        }
    }

    pub(crate) fn der(pem: &[u8]) -> Vec<u8> {
        crate::keys::certificate_der(pem).expect("pem").to_vec()
    }

    pub(crate) fn plist(
        account: &str,
        valid_as_of: &str,
        duration: i64,
        hashes: &[&str],
    ) -> String {
        let hashes: String = hashes
            .iter()
            .map(|h| format!("<string>{h}</string>"))
            .collect();
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>altDsID</key><string>{account}</string>
<key>ValidAsOf</key><date>{valid_as_of}</date>
<key>SuggestValidDuration</key><integer>{duration}</integer>
<key>ValidatedEmailHashes</key><array>{hashes}</array>
<key>ValidatedPhoneHashes</key><array><string>ABCDEF</string></array>
</dict></plist>"#
        )
    }

    #[test]
    fn a_leaf_that_chains_to_the_root_names_its_account() {
        let apple = FakeApple::new();
        let (cert, _) = apple.leaf("peer", "com.apple.idms.appleid.prd.ACCOUNT-1");
        let (root, int) = (apple.root(), apple.intermediate());
        assert_eq!(
            certificate_account_with(&der(&cert), &root, &[&int]),
            "ACCOUNT-1"
        );
        // Without the intermediate the leaf alone cannot be verified.
        assert_eq!(certificate_account_with(&der(&cert), &root, &[]), "");
        // Chains, but not an AirDrop identity.
        let (other, _) = apple.leaf("other", "someone else");
        assert_eq!(certificate_account_with(&der(&other), &root, &[&int]), "");
    }

    #[test]
    fn apples_name_in_a_self_signed_certificate_is_not_apple() {
        let apple = FakeApple::new();
        let dir = tempfile::tempdir().expect("tempdir");
        let (cert, _) = crate::keys::tests::make_pair(
            dir.path(),
            "com.apple.idms.appleid.prd.ACCOUNT-1",
            &["-newkey", "rsa:2048"],
        );
        assert_eq!(
            certificate_account_with(&der(&cert), &apple.root(), &[&apple.intermediate()]),
            ""
        );
        assert_eq!(certificate_account_with(b"", &apple.root(), &[]), "");
        assert_eq!(certificate_account_with(b"garbage", &apple.root(), &[]), "");
    }

    #[test]
    fn a_signed_record_is_read_and_a_foreign_one_refused() {
        let apple = FakeApple::new();
        let record = apple.record(&plist("ACCOUNT-1", "2026-01-01T00:00:00Z", 3600, &["AbCd"]));
        let r = verify_record_with(&record, &apple.intermediate()).expect("verifies");
        assert_eq!(r.account, "ACCOUNT-1");
        assert_eq!(
            r.hashes,
            ["abcd".to_owned(), "abcdef".to_owned()]
                .into_iter()
                .collect::<BTreeSet<_>>()
        );
        assert_eq!(r.expires, Some(1_767_225_600.0 + 3600.0));
        assert!(r.expired);
        // Another hierarchy's intermediate does not verify it.
        let other = FakeApple::new();
        assert!(verify_record_with(&record, &other.intermediate()).is_none());
        assert!(verify_record_with(b"", &apple.intermediate()).is_none());
        assert!(verify_record_with(b"\x30\x82junk", &apple.intermediate()).is_none());
    }

    /// Anchored at Apple's root, any certificate Apple issues could sign a
    /// record, including the AirDrop certificate of any Apple ID: its holder
    /// could claim anyone's email and phone hashes and pass Contacts Only.
    #[test]
    fn only_the_record_signer_under_the_record_ca_is_trusted() {
        let apple = FakeApple::new();
        let forged = plist("EVIL", "2026-01-01T00:00:00Z", 3600, &["AbCd"]);
        let anchor = apple.intermediate();
        // An AirDrop identity's leaf, from the record CA itself.
        let by_peer =
            apple.record_signed_by("int", "peer", "com.apple.idms.appleid.prd.EVIL", &forged);
        assert!(verify_record_with(&by_peer, &anchor).is_none());
        // The right name, from another CA under the same root.
        apple.intermediate_named("sibling", "Fake Sibling Intermediate");
        let by_sibling = apple.record_signed_by(
            "sibling",
            "sibling-signer",
            "AppleIDValidationRecordSigning05",
            &forged,
        );
        assert!(verify_record_with(&by_sibling, &anchor).is_none());
        // The name is a prefix match: Apple numbers its signers.
        let by_next = apple.record_signed_by(
            "int",
            "next-signer",
            "AppleIDValidationRecordSigning06",
            &forged,
        );
        assert_eq!(
            verify_record_with(&by_next, &anchor).map(|r| r.account),
            Some("EVIL".to_owned())
        );
        // A genuine signer alongside another: openssl verifies both, and
        // the record is refused for not having exactly one.
        let d = apple.dir.path();
        run(
            d,
            &[
                "cms",
                "-sign",
                "-binary",
                "-nodetach",
                "-outform",
                "DER",
                "-in",
                "record.plist",
                "-signer",
                "next-signer.pem",
                "-inkey",
                "next-signer.key",
                "-signer",
                "peer.pem",
                "-inkey",
                "peer.key",
                "-certfile",
                "int.pem",
                "-out",
                "two.cms",
            ],
        );
        let two = fs::read(d.join("two.cms")).expect("record");
        assert!(verify_record_with(&two, &anchor).is_none());
    }

    #[test]
    fn a_record_that_expands_past_its_size_is_refused() {
        let mut dict = plist::Dictionary::new();
        dict.insert("altDsID".into(), "A".into());
        dict.insert(
            "Pad".into(),
            plist::Value::Array(vec![plist::Value::Data(vec![0x41; 30_000]); 1_000]),
        );
        let mut bomb = Vec::new();
        plist::Value::Dictionary(dict)
            .to_writer_binary(&mut bomb)
            .unwrap();
        // About 32 KB, decoding to 30 MB.
        assert!(bomb.len() < 64 << 10);
        assert_eq!(record_from_plist(&bomb, 0.0), None);
    }

    #[test]
    fn the_vendored_apple_root_refuses_a_synthetic_record() {
        let apple = FakeApple::new();
        let record = apple.record(&plist("A", "2026-01-01T00:00:00Z", 1, &[]));
        assert!(crate::apple::verify_record(&record).is_none());
        let (cert, _) = apple.leaf("peer", "com.apple.idms.appleid.prd.A");
        assert_eq!(crate::apple::certificate_account(&der(&cert)), "");
    }

    /// Apple's first Application Integration CA, as first vendored, expired
    /// on 2026-10-21. Apple re-issued it with the same name and key, valid
    /// until 2028-10-04. Trusting the expired copy refuses every Contacts Only
    /// sender it issued, even when the sender sends the renewed one (#75).
    #[test]
    fn every_vendored_intermediate_chains_to_the_root_after_2026_10_21() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_file(&dir.path().join("root.pem"), crate::apple::ROOT_CA_PEM).expect("root");
        for (i, (pem, name)) in crate::apple::INTERMEDIATES_PEM
            .iter()
            .zip(crate::apple::INTERMEDIATE_NAMES)
            .enumerate()
        {
            let file = format!("int{i}.pem");
            write_file(&dir.path().join(&file), pem).expect("intermediate");
            let out = openssl(
                &[
                    "verify",
                    "-attime",
                    "1792627200",
                    "-CAfile",
                    "root.pem",
                    &file,
                ],
                None,
                Some(dir.path()),
                None,
            )
            .expect("openssl runs");
            assert!(
                out.status.success(),
                "{name}: {}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    #[test]
    fn expiry_follows_valid_as_of_plus_duration() {
        let p = plist("A", "2030-01-01T00:00:00Z", 60, &[]);
        let r = record_from_plist(p.as_bytes(), 0.0).expect("plist");
        assert_eq!(r.expires, Some(1_893_456_000.0 + 60.0));
        assert!(!r.expired);
        assert!(
            record_from_plist(p.as_bytes(), 1_893_456_061.0)
                .expect("plist")
                .expired
        );
        assert!(record_from_plist(b"<plist><array/></plist>", 0.0).is_none());
        assert!(record_from_plist(b"not a plist", 0.0).is_none());
    }

    #[test]
    fn subject_parsing_reads_the_common_name_line() {
        // What `-nameopt multiline` prints, on OpenSSL 3.0 and later alike.
        assert_eq!(
            account_from_subject(
                "subject=\n    organizationName          = Apple Inc.\n    commonName                = com.apple.idms.appleid.prd.X1\n"
            ),
            "X1"
        );
        assert_eq!(
            account_from_subject("subject=\n    commonName                = airdrop\n"),
            ""
        );
        assert_eq!(
            account_from_subject("subject=\n    organizationName          = x\n"),
            ""
        );
        // The one-line forms are not read: the command always asks for
        // multiline, so neither OpenSSL 3.0's nor 3.x's default can matter.
        assert_eq!(
            account_from_subject("subject=O = Apple Inc., CN = com.apple.idms.appleid.prd.X1\n"),
            ""
        );
    }
}
