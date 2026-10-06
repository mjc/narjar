//! Narjar's supported Rust API is limited to NAR streaming and content identities.
//!
//! Narjar is primarily a command-line cache server and uploader. The supported
//! library surface is [`nar`], [`nar_encode`], and [`object`]. Set
//! `default-features = false` to use these without the application's HTTP,
//! compression, or SQLite dependencies. The default `application` feature builds
//! the command-line program. The HTTP server,
//! storage backends, authorization, maintenance, metrics, and narinfo plumbing
//! are implementation details used by the binary and may change without notice. They are
//! available under the hidden `__private` module only so the binary and repository integration
//! tests can share the implementation; consumers should not depend on those paths.
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
//! Implementation modules are intentionally not exported at the crate root:
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
