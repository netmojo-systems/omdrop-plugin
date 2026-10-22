//! AirDrop protocol pieces shared by the Omdrop receiver and sender.
//!
//! Apple's wire identifiers are not ours to rename: the endpoints really are
//! `/Discover`, `/Ask` and `/Upload`, and the mDNS service type really is
//! `_airdrop._tcp`.
//!
//! - [`archive`]: `/Upload` bodies: DVZip and gzip decoding, DVZip encoding,
//!   CPIO read and write, bounded extraction, safe file names.
//! - [`contacts`]: the Contacts Only policy.
//! - [`http`]: the receiver's HTTP/1.1 framing, limits and read deadlines.
//! - [`safeplist`]: property lists from peers, parsed under size and depth
//!   limits (never `plist::Value::from_reader` on untrusted bytes). Defined
//!   in omdrop-identity, which every crate reading one depends on.
//! - [`tls`]: rustls configurations built from an [`omdrop_identity::Identity`].
//! - [`debugdump`]: opt-in, redacted protocol dumps (`OMDROP_DEBUG`).
//! - [`net`]: interface addresses, EUI-64 link-local addresses, scoped sockets.

pub mod archive;
pub mod contacts;
pub mod debugdump;
pub mod http;
pub mod net;
pub use omdrop_identity::safeplist;
pub mod tls;
