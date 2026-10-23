//! The Omdrop identity contract (`docs/identity-contract.md`).
//!
//! One implementation for every Omdrop program: the receiver, the sender, the
//! advertisers, the root helper and the `omdrop` command. It replaces two
//! Python implementations of the same contract, `identity.py`/`lifecycle.py`
//! in omdrop-plugin and `awdl_identity.py` in omdrop-awdl, and must pass the
//! shared `tests/identity-vectors.json`.
//!
//! The types and functions re-exported here are the stable surface other
//! crates build against. Their signatures are a contract between crates:
//! change one only together with every caller.
//!
//! [`safeplist`] lives here, not in omdrop-proto, because every crate that
//! reads a property list it did not write depends on this one: validation
//! records (here and in omdrop-adv), received `.webloc` files (omdrop-cli),
//! and the AirDrop protocol (omdrop-proto re-exports it).

use std::fmt;
use std::path::PathBuf;

use zeroize::Zeroizing;

mod applecheck;
mod args;
mod asuser;
mod contract;
mod fsx;
mod keyring;
mod keys;
mod lifecycle;
mod op;
mod resolver;
mod selfsigned;
mod sys;
mod user;

pub mod safeplist;

/// Which identity selection chose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// The Apple identity fetched from 1Password, held in the kernel keyring.
    Cache,
    /// The Apple identity in `~/.omdrop/keys`.
    Disk,
    /// The generated `*.self-signed.pem` pair.
    SelfSigned,
}

impl Source {
    /// The contract's name for this source: `cache`, `disk`, `self-signed`.
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Cache => "cache",
            Source::Disk => "disk",
            Source::SelfSigned => "self-signed",
        }
    }
}

/// The selected identity, with the bytes to present.
///
/// `certificate_pem` may hold a chain (leaf first). `key_pem` is secret and is
/// zeroed on drop. `record` is the DER validation record, presented only with
/// the certificate it belongs to.
pub struct Identity {
    pub source: Source,
    pub certificate_pem: Vec<u8>,
    pub key_pem: Zeroizing<Vec<u8>>,
    pub record: Option<Vec<u8>>,
    /// Contract warnings, sorted: `unknown-mode`, `disk-incomplete`, `disk-mismatch`.
    pub warnings: Vec<String>,
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("source", &self.source)
            .field(
                "certificate_pem",
                &format_args!("<{} bytes>", self.certificate_pem.len()),
            )
            .field("key_pem", &"<redacted>")
            .field("record", &self.record.as_ref().map(|r| r.len()))
            .field("warnings", &self.warnings)
            .finish()
    }
}

/// A contract error code. `Display` prints the code alone, which is what
/// callers report. `resolve` returns: selection's `window-unparseable`,
/// `window-expired`, `cache-missing`, `cache-malformed`, `cache-mismatch`,
/// `cache-expired`, `disk-missing`, `disk-mismatch`, `self-signed-half-pair`,
/// `self-signed-missing`; and the I/O failures `invoking-user-invalid`,
/// `settings-unreadable`, `cache-unreadable`, `cache-unreadable-as-root`,
/// `cache-protection-unavailable`, `disk-record-unreadable`,
/// `self-signed-create-failed`, `self-signed-unreadable`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityError {
    pub code: String,
}

impl IdentityError {
    pub fn new(code: impl Into<String>) -> Self {
        IdentityError { code: code.into() }
    }
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.code)
    }
}

impl std::error::Error for IdentityError {}

/// How to resolve.
#[derive(Clone, Debug, Default)]
pub struct ResolveOptions {
    /// `--keys DIR`: read the disk trio and the self-signed pair from
    /// `DIR/keys/` instead of `~/.omdrop/keys/` (contract: "An explicit keys
    /// directory").
    pub keys_dir: Option<PathBuf>,
    /// The computer name a newly created self-signed certificate carries.
    /// `None` uses the host name.
    pub computer_name: Option<String>,
    /// Whether a missing self-signed pair may be created. Programs running as
    /// root never create it, whatever this says; they get `self-signed-missing`.
    pub create: bool,
}

/// Resolve the identity for the invoking user (contract: "Running as root"
/// for UID 0). Never fetches from 1Password and never touches a radio.
pub fn resolve(opts: &ResolveOptions) -> Result<Identity, IdentityError> {
    resolver::resolve(opts)
}

/// This machine's host name up to its first dot, as a sender's default
/// `SenderComputerName`.
pub fn short_hostname() -> String {
    let full = sys::hostname();
    full.split('.').next().unwrap_or(&full).to_owned()
}

/// Apple's public CAs and the checks that need them: whether a certificate
/// chains to Apple and which account it names, and what a validation record
/// says once its signature checks out. Ported from omdrop-plugin's
/// `contacts.py`; the receiver's Contacts policy and `omdrop identity` both
/// use it.
pub mod apple {
    /// Apple Root CA, PEM. Vendored: public, no account needed.
    pub const ROOT_CA_PEM: &[u8] = include_bytes!("../certs/apple_root_ca.pem");
    /// Apple Application Integration 2 CA, PEM: the issuer of the certificate
    /// Apple signs validation records with, and the only certificate a
    /// record's signature may chain to.
    pub const RECORD_SIGNING_CA_PEM: &[u8] = include_bytes!("../certs/apple-aai2-ca.pem");
    /// Apple's issuing intermediates, PEM. A sender presents only its leaf,
    /// so a chain to the root needs these.
    pub const INTERMEDIATES_PEM: &[&[u8]] = &[
        include_bytes!("../certs/apple-aai-ca.pem"),
        RECORD_SIGNING_CA_PEM,
    ];
    /// The subject common names of [`INTERMEDIATES_PEM`], in the same order.
    pub const INTERMEDIATE_NAMES: &[&str] = &[
        "Apple Application Integration Certification Authority",
        "Apple Application Integration 2 Certification Authority",
    ];

    /// What a validation record says, once Apple's signature over it checks out.
    #[derive(Clone, Debug, PartialEq)]
    pub struct Record {
        /// `altDsID`: the Apple account.
        pub account: String,
        /// `ValidatedEmailHashes` and `ValidatedPhoneHashes`, lowercased.
        pub hashes: std::collections::BTreeSet<String>,
        /// `ValidAsOf` + `SuggestValidDuration`, Unix seconds, if both present.
        pub expires: Option<f64>,
        pub expired: bool,
    }

    /// Apple's signature over a DER validation record, and its contents.
    /// `None` unless the record is signed by one certificate named
    /// `AppleIDValidationRecordSigning…` issued by [`RECORD_SIGNING_CA_PEM`].
    pub fn verify_record(record: &[u8]) -> Option<Record> {
        crate::applecheck::verify_record_with(record, RECORD_SIGNING_CA_PEM)
    }

    /// The Apple account a DER certificate belongs to, or `""` when it does
    /// not verify to Apple's root through the vendored intermediates. Never a
    /// name check: anyone can write Apple's name into a self-signed certificate.
    pub fn certificate_account(der: &[u8]) -> String {
        crate::applecheck::certificate_account_with(der, ROOT_CA_PEM, INTERMEDIATES_PEM)
    }
}

/// `identity.py`'s command line, in process, for `omdrop`: `begin --name N`,
/// `window --seq N`, `stop-begin`, `stop-end`, `lock`, `unlock`,
/// `status [--json]`, `import [--vault V] [--title T]`,
/// `use ITEM [--vault V] [--account A]`, `1password-off`,
/// `ensure-self-signed --name N`.
pub mod cli {
    use std::io::Write;

    /// Run one subcommand. Writes exactly what `python3 identity.py ARGS`
    /// writes to stdout and stderr, and returns its exit status.
    pub fn run(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> i32 {
        crate::lifecycle::main(args, out, err)
    }
}
