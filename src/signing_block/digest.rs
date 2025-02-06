//! Digesting functions for APK
//!
//! Gated behind the `hash` feature

#![cfg(feature = "hash")]

use std::{
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom},
    mem,
};

use super::algorithms::Algorithms;

/// Start byte for chunk
const START_BYTE_CHUNK: u8 = 0xa5; // 165
/// Start byte for end chunk
const START_BYTE_END_CHUNK: u8 = 0x5a; // 90

/// Chunk size
const CHUNK_SIZE: usize = 1 << 20; // 1MB

/// Digest a chunk of data
fn digest_chunk(chunk: &[u8], sig: &Algorithms) -> Vec<u8> {
    let chunk_size = (chunk.len() as u32).to_le_bytes()[..].to_vec();
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

/// File offsets of the APK (a zip file)
///
/// <https://source.android.com/docs/security/features/apksigning/v2>
///
/// |       Content of ZIP entries  | APK Signing Block |   Central Directory     |    End of Central Directory   |
/// |-------------------------------|-------------------|-------------------------|-------------------------------|
/// | start_content -> stop_content |                   | start_cd   ->   stop_cd | start_eocd    ->    stop_eocd |
///
/// Some fields are the same as the others, but they are separated for clarity:
///
/// - [`FileOffsets::stop_cd`] and [`FileOffsets::start_eocd`] are generally the same
/// - [`FileOffsets::stop_content`] and [`FileOffsets::start_cd`] are the same if there is no APK Signing Block
#[derive(Debug)]
pub struct FileOffsets {
    /// Start index of content
    pub start_content: usize,
    /// Stop index of content
    pub stop_content: usize,
    /// Start index of central directory
    pub start_cd: usize,
    /// Stop index of central directory
    pub stop_cd: usize,
    /// Start index of end of central directory
    pub start_eocd: usize,
    /// Stop index of end of central directory
    pub stop_eocd: usize,
}

impl FileOffsets {
    /// Create a new instance of `FileOffsets`
    pub fn new(stop_content: usize, start_cd: usize, stop_cd: usize, stop_eocd: usize) -> Self {
        Self {
            start_content: 0,
            stop_content,
            start_cd,
            stop_cd,
            start_eocd: stop_cd,
            stop_eocd,
        }
    }

    /// Create a new instance of `FileOffsets`
    /// With only 3 arguments, the signature is not included
    pub fn without_signature(stop_content: usize, stop_cd: usize, stop_eocd: usize) -> Self {
        Self::new(stop_content, stop_content, stop_cd, stop_eocd)
    }
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

/// End of Central Directory signature
const EOCD_SIG: usize = 0x06054b50;
/// End of Central Directory signature as u8
const EOCD_SIG_U8: [u8; 4] = (EOCD_SIG as u32).to_le_bytes();
/// Size of the EOCD signature
const SIZE_OF_EOCD_SIG: usize = mem::size_of::<u32>();

/// End of Central Directory Record
#[derive(Debug)]
pub struct EndOfCentralDirectoryRecord {
    /// File offset
    pub file_offset: usize,
    /// Signature
    pub signature: [u8; 4],
    /// Disk number
    pub disk_number: u16,
    /// Disk where the CD starts
    pub disk_with_cd: u16,
    /// Number of CD
    pub num_entries: u16,
    /// Total number CD
    pub total_entries: u16,
    /// Size of the CD
    pub cd_size: u32,
    /// Offset of the CD
    pub cd_offset: u32,
    /// Length of the comment
    pub comment_len: u16,
    /// Comment
    pub comment: Vec<u8>,
}

/// Find the EOCD of the APK file
/// # Errors
/// Returns an error if the file cannot be read
pub fn find_eocd<R: Read + Seek>(
    apk: &mut R,
    file_len: usize,
) -> Result<EndOfCentralDirectoryRecord, io::Error> {
    for i in SIZE_OF_EOCD_SIG..file_len {
        let idx = -(i as i64);
        apk.seek(SeekFrom::End(idx))?;
        let mut reader =
            BufReader::with_capacity(SIZE_OF_EOCD_SIG, apk.take(SIZE_OF_EOCD_SIG as u64));
        let mut buf = [0; SIZE_OF_EOCD_SIG];
        reader.read_exact(&mut buf)?;
        if buf == EOCD_SIG_U8 {
            if i < 22 {
                continue;
            }
            apk.seek(SeekFrom::End(idx))?;
            let mut buff_block: Vec<u8> = vec![0; i];
            apk.read_exact(&mut buff_block)?;
            let disk_number = match buff_block.get(0..2) {
                Some(data) => u16::from_le_bytes(create_fixed_buffer_2(data)),
                None => return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid EOCD")),
            };
            let disk_with_cd = match buff_block.get(2..4) {
                Some(data) => u16::from_le_bytes(create_fixed_buffer_2(data)),
                None => return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid EOCD")),
            };
            let num_entries = match buff_block.get(4..6) {
                Some(data) => u16::from_le_bytes(create_fixed_buffer_2(data)),
                None => return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid EOCD")),
            };
            let total_entries = match buff_block.get(6..8) {
                Some(data) => u16::from_le_bytes(create_fixed_buffer_2(data)),
                None => return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid EOCD")),
            };
            let cd_size = match buff_block.get(8..12) {
                Some(data) => u32::from_le_bytes(create_fixed_buffer_4(data)),
                None => return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid EOCD")),
            };
            let cd_offset = match buff_block.get(12..16) {
                Some(data) => u32::from_le_bytes(create_fixed_buffer_4(data)),
                None => return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid EOCD")),
            };
            let comment_len = match buff_block.get(16..18) {
                Some(data) => u16::from_le_bytes(create_fixed_buffer_2(data)),
                None => return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid EOCD")),
            };
            let comment = match buff_block.get(18..) {
                Some(data) => data.to_vec(),
                None => return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid EOCD")),
            };
            let eocd = EndOfCentralDirectoryRecord {
                file_offset: file_len - i,
                signature: buf,
                disk_number,
                disk_with_cd,
                num_entries,
                total_entries,
                cd_size,
                cd_offset,
                comment_len,
                comment,
            };
            return Ok(eocd);
        }
    }
    Err(io::Error::new(io::ErrorKind::NotFound, "EOCD not found"))
}

/// Create a fixed buffer of 4 bytes
pub(crate) fn create_fixed_buffer_4(buf: &[u8]) -> [u8; 4] {
    let mut buffer = [0; 4];
    buffer.copy_from_slice(buf);
    buffer
}

/// Create a fixed buffer of 2 bytes
pub(crate) fn create_fixed_buffer_2(buf: &[u8]) -> [u8; 2] {
    let mut buffer = [0; 2];
    buffer.copy_from_slice(buf);
    buffer
}
