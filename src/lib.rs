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
    clippy::cargo
)]
#![warn(clippy::multiple_crate_versions)]

use std::fs;
use std::io::BufReader;
use std::io::Seek;

pub mod common;
pub mod signing_block;
pub mod utils;

// re-export
pub use signing_block::algorithms::Algorithms;
pub use signing_block::digest::digest_apk;
pub use signing_block::scheme_v2::{SignatureSchemeV2, SIGNATURE_SCHEME_V2_BLOCK_ID};
pub use signing_block::scheme_v3::{SignatureSchemeV3, SIGNATURE_SCHEME_V3_BLOCK_ID};
pub use signing_block::{
    scheme_v2, scheme_v3, RawData, SigningBlock, ValueSigningBlock, MAGIC, MAGIC_LEN,
};
pub use utils::MyReader;

// shortcuts
use utils::add_space;

/// Main function
/// # Errors
/// Return an error if the file cannot be opened
pub fn real_main() -> Result<i32, Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <filename>", args[0]);
        return Ok(1);
    }
    let fname = std::path::Path::new(&args[1]);
    let file = fs::File::open(fname)?;
    let mut reader = BufReader::new(file);

    let file_len = reader.seek(std::io::SeekFrom::End(0))? as usize;
    println!("{} length: {} bytes", fname.display(), file_len);
    // find the magic string starting from the end of the file
    let sig_block = SigningBlock::from_reader(reader, file_len, 0)?;
    println!(
        "APK Signing Block is between {} and {} with a size of {} bytes",
        sig_block.file_offset_start,
        sig_block.file_offset_end,
        sig_block.size_of_block_start + 8
    );
    Ok(0)
}
