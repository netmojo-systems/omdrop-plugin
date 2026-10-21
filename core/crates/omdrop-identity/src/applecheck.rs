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
pub(crate) fn record_from_plist(payload: &[u8], now: f64) -> Option<Record> {
    let value = plist::Value::from_reader(std::io::Cursor::new(payload)).ok()?;
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

/// `openssl cms -verify` against `root_pem`, then the record's contents.
///
/// `-purpose any` is required: the signer is a record-signing certificate,
/// not an S/MIME one, so openssl's default purpose check rejects genuine
/// records.
pub(crate) fn verify_record_with(record: &[u8], root_pem: &[u8]) -> Option<Record> {
    if record.is_empty() || root_pem.is_empty() {
        return None;
    }
    let dir = workdir(root_pem)?;
    let ca = dir.path().join("ca.pem");
    let out = dir.path().join("out.bin");
    let run = openssl(
        &[
            "cms".as_ref(),
            "-verify".as_ref(),
            "-inform".as_ref(),
            "DER".as_ref(),
            "-CAfile".as_ref(),
            ca.as_os_str(),
            "-purpose".as_ref(),
            "any".as_ref(),
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
    let payload = fs::read(&out).ok()?;
    record_from_plist(&payload, now_secs())
}

/// The account in `openssl x509 -subject -nameopt multiline` output: the
/// `commonName = value` line (the last, as the plugin's contacts.py reads it),
/// if it carries Apple's prefix. The one-line default is `CN = value` on
/// OpenSSL 3.0 (Debian 12, Ubuntu 22.04 and 24.04) and `CN=value` later, so
/// searching it for `CN=` refused every Apple certificate on 3.0 (plugin #67).
fn account_from_subject(subject: &str) -> String {
    let mut cn = "";
    for line in subject.lines() {
        if let Some((key, value)) = line.split_once('=')
            && key.trim() == "commonName"
        {
            cn = value.trim();
        }
    }
    cn.strip_prefix(CN_PREFIX).unwrap_or("").to_owned()
}

/// The Apple account a DER client certificate belongs to, or `""`.
///
/// The certificate must actually verify to `root_pem` through
/// `intermediates` (a sender presents only its leaf). Never a name check: an
/// earlier version checked only that the issuer name said Apple, and a name
/// is a string an attacker writes into their own self-signed certificate.
/// Everyone-mode peers present a self-signed `CN=airdrop`; those yield "".
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
    /// -> leaf `CN=com.apple.idms.appleid.prd.<account>`, plus a record signer.
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
            run(
                d,
                &[
                    "req",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-subj",
                    "/CN=Fake Intermediate",
                    "-keyout",
                    "int.key",
                    "-out",
                    "int.csr",
                ],
            );
            run(
                d,
                &[
                    "x509",
                    "-req",
                    "-in",
                    "int.csr",
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
                    "int.pem",
                ],
            );
            FakeApple { dir }
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
            let d = self.dir.path();
            let (key, csr, pem) = (
                format!("{name}.key"),
                format!("{name}.csr"),
                format!("{name}.pem"),
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
                    "int.pem",
                    "-CAkey",
                    "int.key",
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

        /// A DER CMS record over `plist`, signed by a leaf of this hierarchy.
        pub(crate) fn record(&self, plist_xml: &str) -> Vec<u8> {
            let d = self.dir.path();
            if !d.join("signer.pem").exists() {
                self.leaf("signer", "Fake Record Signer");
            }
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
                    "signer.pem",
                    "-inkey",
                    "signer.key",
                    "-certfile",
                    "int.pem",
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
        let r = verify_record_with(&record, &apple.root()).expect("verifies");
        assert_eq!(r.account, "ACCOUNT-1");
        assert_eq!(
            r.hashes,
            ["abcd".to_owned(), "abcdef".to_owned()]
                .into_iter()
                .collect::<BTreeSet<_>>()
        );
        assert_eq!(r.expires, Some(1_767_225_600.0 + 3600.0));
        assert!(r.expired);
        // Another hierarchy's root does not verify it.
        let other = FakeApple::new();
        assert!(verify_record_with(&record, &other.root()).is_none());
        assert!(verify_record_with(b"", &apple.root()).is_none());
        assert!(verify_record_with(b"\x30\x82junk", &apple.root()).is_none());
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
