//! Digesting functions for APK
//!
//! Gated behind the `hash` feature

#![cfg(feature = "hash")]

use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom};

use crate::zip::FileOffsets;

use super::algorithms::Algorithms;

/// Start byte for chunk
const START_BYTE_CHUNK: u8 = 0xa5; // 165
/// Start byte for end chunk
const START_BYTE_END_CHUNK: u8 = 0x5a; // 90

/// Chunk size
const CHUNK_SIZE: usize = 1 << 20; // 1MB

/// Digest a chunk of data
fn digest_chunk(chunk: &[u8], sig: &Algorithms) -> Vec<u8> {
    let chunk_size = (chunk.len() as u32).to_le_bytes().to_vec();
    let mut data = vec![START_BYTE_CHUNK];
    data.extend(chunk_size);
    data.extend(chunk);
    sig.hash(&data)
}

/// Digest the contents of ZIP entries
/// # Errors
/// Returns an error if the file cannot be read
pub fn digest_zip_contents<R: Read + Seek>(
    file: &mut R,
    start: usize,
    size: usize,
    sig: &Algorithms,
) -> Result<Vec<Vec<u8>>, io::Error> {
    let start = (start) as u64;
    file.seek(SeekFrom::Start(start))?;
    let next_offset = (size) as u64;
    let taker = file.take(next_offset);
    let mut reader = BufReader::with_capacity(CHUNK_SIZE, taker);
    let mut digestives = Vec::new();
    loop {
        let chunk = reader.fill_buf()?;
        let length = chunk.len();
        if length == 0 {
            break;
        }
        digestives.push(digest_chunk(chunk, sig));
        reader.consume(length);
    }
    Ok(digestives)
}

/// Digest the central directory
/// # Errors
/// Returns an error if the file cannot be read
pub fn digest_central_directory<R: Read + Seek>(
    file: &mut R,
    start: usize,
    size: usize,
    sig: &Algorithms,
) -> Result<Vec<Vec<u8>>, io::Error> {
    let next_offset = (start) as u64;
    file.seek(SeekFrom::Start(next_offset))?; // skip the signing block
    let taker = file.take((size) as u64);
    let mut reader = BufReader::with_capacity(CHUNK_SIZE, taker);
    let mut digestives = Vec::new();
    loop {
        let chunk = reader.fill_buf()?;
        let length = chunk.len();
        if length == 0 {
            break;
        }
        digestives.push(digest_chunk(chunk, sig));
        reader.consume(length);
    }
    Ok(digestives)
}

/// Digest the end of central directory
/// # Errors
/// Returns an error if the file cannot be read
pub fn digest_end_of_central_directory<R: Read + Seek>(
    file: &mut R,
    start: usize,
    eocd_size: usize,
    central_directory_offset: usize,
    sig: &Algorithms,
) -> Result<Vec<Vec<u8>>, io::Error> {
    let next_offset = (start) as u64;
    file.seek(SeekFrom::Start(next_offset))?;
    let mut eocd_buff = Vec::with_capacity(eocd_size);
    file.read_to_end(&mut eocd_buff)?;
    // little manipulation to change the offset of the central directory offset
    let first_part = match eocd_buff.get(..16) {
        Some(data) => data,
        None => return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid EOCD")),
    };
    let second_part = match eocd_buff.get(20..) {
        Some(data) => data,
        None => return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid EOCD")),
    };
    let eocd_buff = [
        first_part.to_vec(),
        (central_directory_offset as u32).to_le_bytes().to_vec(),
        second_part.to_vec(),
    ]
    .concat();
    let reader = std::io::Cursor::new(eocd_buff);
    let mut reader = BufReader::with_capacity(CHUNK_SIZE, reader);
    let mut digestives = Vec::new();
    loop {
        let chunk = reader.fill_buf()?;
        let length = chunk.len();
        if length == 0 {
            break;
        }
        let digest = digest_chunk(chunk, sig);
        digestives.push(digest);
        reader.consume(length);
    }
    Ok(digestives)
}

/// Digest the final digest from all digests
pub fn digest_final_digest(chunks: Vec<Vec<u8>>, sig: &Algorithms) -> Vec<u8> {
    let mut final_chunk = vec![START_BYTE_END_CHUNK];
    final_chunk.extend((chunks.len() as u32).to_le_bytes());
    final_chunk.extend(chunks.concat());
    sig.hash(&final_chunk)
}

/// Digest the APK file
/// # Errors
/// Returns an error if the file cannot be read
pub fn digest_apk<R: Read + Seek>(
    apk: &mut R,
    offsets: &FileOffsets,
    algo: &Algorithms,
) -> Result<Vec<u8>, io::Error> {
    apk.seek(SeekFrom::Start(0))?;
    let FileOffsets {
        start_content,
        stop_content,
        start_cd,
        stop_cd,
        start_eocd,
        stop_eocd,
    } = *offsets;
    let mut digestives = Vec::new();
    digestives.append(&mut digest_zip_contents(
        apk,
        start_content,
        stop_content - start_content,
        algo,
    )?);
    // digest central directory
    digestives.append(&mut digest_central_directory(
        apk,
        start_cd,
        stop_cd - start_cd,
        algo,
    )?);
    // digest end of central directory
    digestives.append(&mut digest_end_of_central_directory(
        apk,
        start_eocd,
        stop_eocd - start_eocd,
        stop_content,
        algo,
    )?);
    // create the final digest
    let final_digest = digest_final_digest(digestives, algo);
    Ok(final_digest)
}
