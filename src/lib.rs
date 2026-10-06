//! Streaming NAR codecs and typed content identities.
//!
//! The supported library modules are [`nar`], [`nar_encode`], and [`object`]. Set
//! `default-features = false` to use these without the application's HTTP,
//! compression, or SQLite dependencies. The default `application` feature builds
//! the command-line program. The binary and repository integration tests share
//! application code through the hidden `__private` module. Its paths are not
//! supported for downstream use and may change without notice.
//!
//! ```
//! use narjar::object::{NarHash, NarIdentity, NarSize};
//!
//! let identity = NarIdentity::new(NarHash::from_digest([0; 32]), NarSize::new(128));
//! assert_eq!(identity.size().get(), 128);
//! ```
//!
//! Encode and decode a NAR stream without materializing a filesystem tree:
//!
//! ```
//! use std::{convert::Infallible, io::Cursor};
//! use narjar::{
//!     nar::{Decoder, Event as DecodeEvent},
//!     nar_encode::{Encoder, Event},
//! };
//!
//! let mut encoder = Encoder::new(Vec::new())?;
//! encoder.push(Event::BeginDirectory)?;
//! encoder.push(Event::EndDirectory)?;
//! let (bytes, encoded) = encoder.finish()?;
//!
//! let mut sink = |_: DecodeEvent<'_>| -> Result<(), Infallible> { Ok(()) };
//! let decoded = Decoder::new(Cursor::new(bytes)).decode(&mut sink)?;
//! assert_eq!(decoded.raw_sha256, encoded.raw_sha256);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! Application modules are not exported at the crate root:
//!
//! ```compile_fail
//! let _ = narjar::storage::StorageBackend::Flat;
//! ```

#![warn(missing_docs)]

#[cfg(feature = "application")]
mod implementation;

pub mod nar;
pub mod nar_encode;
pub mod object;

#[doc(hidden)]
#[cfg(feature = "application")]
pub mod __private {
    pub use crate::implementation::{
        auth, filesystem, http, http_server, inventory, maintenance, metrics, nar, nar_compression,
        nar_encode, narinfo, object, records, storage, token_file,
    };
}

#[cfg(feature = "application")]
pub(crate) use implementation::{
    auth, filesystem, http_server, inventory, maintenance, metrics, nar_compression, narinfo,
    records, storage, token_file,
};
