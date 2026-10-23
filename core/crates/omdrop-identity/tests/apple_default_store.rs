//! openssl's default trust store must not stand in for Apple's CAs. A CA in
//! `SSL_CERT_DIR` (on a real machine, `/etc/ssl/certs`: every public CA) is
//! trusted by `-CAfile` checks unless they say `-no-CApath -no-CAstore`.
//! One test in this binary: it sets `SSL_CERT_DIR` for the whole process.

use std::path::Path;
use std::process::Command;

use omdrop_identity::apple;

fn openssl(dir: &Path, args: &[&str]) {
    let out = Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("openssl runs");
    assert!(
        out.status.success(),
        "openssl {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A leaf `name` with common name `cn`, issued by `ca`.
fn leaf(dir: &Path, name: &str, cn: &str) {
    openssl(
        dir,
        &[
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            &format!("/CN={cn}"),
            "-keyout",
            &format!("{name}.key"),
            "-out",
            &format!("{name}.csr"),
        ],
    );
    openssl(
        dir,
        &[
            "x509",
            "-req",
            "-in",
            &format!("{name}.csr"),
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-days",
            "2",
            "-out",
            &format!("{name}.pem"),
        ],
    );
}

#[test]
fn a_ca_in_the_default_store_vouches_for_no_record_and_no_peer() {
    let work = tempfile::tempdir().unwrap();
    let store = tempfile::tempdir().unwrap();
    let d = work.path();
    openssl(
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
            "/CN=Some Public CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=keyCertSign,cRLSign",
            "-keyout",
            "ca.key",
            "-out",
            "ca.pem",
        ],
    );
    std::fs::copy(d.join("ca.pem"), store.path().join("ca.pem")).unwrap();
    openssl(store.path(), &["rehash", "."]);
    leaf(d, "signer", "AppleIDValidationRecordSigning05");
    leaf(d, "peer", "com.apple.idms.appleid.prd.ACCOUNT-1");
    std::fs::write(
        d.join("record.plist"),
        "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict>\
         <key>altDsID</key><string>ACCOUNT-1</string></dict></plist>",
    )
    .unwrap();
    openssl(
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
            "-out",
            "record.cms",
        ],
    );
    openssl(
        d,
        &[
            "x509", "-in", "peer.pem", "-outform", "DER", "-out", "peer.der",
        ],
    );
    let record = std::fs::read(d.join("record.cms")).unwrap();
    let peer = std::fs::read(d.join("peer.der")).unwrap();
    // SAFETY: the only test in this binary, so no other thread reads the
    // environment while it changes.
    unsafe { std::env::set_var("SSL_CERT_DIR", store.path()) };
    // The store really is trusted by a plain -CAfile check.
    let plain = Command::new("openssl")
        .args(["verify", "-CAfile", "peer.pem", "peer.pem"])
        .current_dir(d)
        .output()
        .unwrap();
    assert!(plain.status.success(), "the fixture store is not in effect");
    assert_eq!(apple::verify_record(&record), None);
    assert_eq!(apple::certificate_account(&peer), "");
}
