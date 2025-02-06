//! # APK Signing Block
//! This library is used to extract the APK Signing Block from an APK file.
//!
//! CLI usage:
//! ```shell
//! cargo install apksig
//! apksig <filename>
//! ```
//!

#![deny(
    missing_docs,
    clippy::all,
    clippy::missing_docs_in_private_items,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::cargo,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::print_stdout
)]
#![warn(clippy::multiple_crate_versions)]

pub mod apk;
pub mod common;
pub mod signing_block;
pub mod utils;
pub mod zip;

// re-export
#[cfg(feature = "hash")]
pub use signing_block::digest::digest_apk;

pub use apk::Apk;
pub use signing_block::algorithms::Algorithms;
pub use signing_block::scheme_v2::{SignatureSchemeV2, SIGNATURE_SCHEME_V2_BLOCK_ID};
pub use signing_block::scheme_v3::{SignatureSchemeV3, SIGNATURE_SCHEME_V3_BLOCK_ID};
pub use signing_block::{
    scheme_v2, scheme_v3, RawData, SigningBlock, ValueSigningBlock, MAGIC, MAGIC_LEN,
};
pub use utils::MyReader;

// shortcuts
use utils::add_space;
