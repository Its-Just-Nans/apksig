//! Zip file utilities - an APK is a zip file

use std::{
    io::{self, BufReader, Read, Seek, SeekFrom},
    mem,
};

/// End of Central Directory signature
const EOCD_SIG: usize = 0x0605_4b50;
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

impl EndOfCentralDirectoryRecord {
    /// Convert the EOCD to a u8 vector
    pub fn to_u8(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.signature);
        data.extend_from_slice(&self.disk_number.to_le_bytes());
        data.extend_from_slice(&self.disk_with_cd.to_le_bytes());
        data.extend_from_slice(&self.num_entries.to_le_bytes());
        data.extend_from_slice(&self.total_entries.to_le_bytes());
        data.extend_from_slice(&self.cd_size.to_le_bytes());
        data.extend_from_slice(&self.cd_offset.to_le_bytes());
        data.extend_from_slice(&self.comment_len.to_le_bytes());
        data.extend_from_slice(&self.comment);
        data
    }
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
            let disk_number = match buff_block.get(4..6) {
                Some(data) => u16::from_le_bytes(create_fixed_buffer_2(data)),
                None => return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid EOCD")),
            };
            let disk_with_cd = match buff_block.get(6..8) {
                Some(data) => u16::from_le_bytes(create_fixed_buffer_2(data)),
                None => return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid EOCD")),
            };
            let num_entries = match buff_block.get(8..10) {
                Some(data) => u16::from_le_bytes(create_fixed_buffer_2(data)),
                None => return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid EOCD")),
            };
            let total_entries = match buff_block.get(10..12) {
                Some(data) => u16::from_le_bytes(create_fixed_buffer_2(data)),
                None => return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid EOCD")),
            };
            let cd_size = match buff_block.get(12..16) {
                Some(data) => u32::from_le_bytes(create_fixed_buffer_4(data)),
                None => return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid EOCD")),
            };
            let cd_offset = match buff_block.get(16..20) {
                Some(data) => u32::from_le_bytes(create_fixed_buffer_4(data)),
                None => return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid EOCD")),
            };
            let comment_len = match buff_block.get(20..22) {
                Some(data) => u16::from_le_bytes(create_fixed_buffer_2(data)),
                None => return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid EOCD")),
            };
            let comment = match buff_block.get(22..) {
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
pub(crate) const fn create_fixed_buffer_4(buf: &[u8]) -> [u8; 4] {
    let mut buffer = [0; 4];
    buffer.copy_from_slice(buf);
    buffer
}

/// Create a fixed buffer of 2 bytes
pub(crate) const fn create_fixed_buffer_2(buf: &[u8]) -> [u8; 2] {
    let mut buffer = [0; 2];
    buffer.copy_from_slice(buf);
    buffer
}

/// File offsets of the APK (a zip file)
///
/// <https://source.android.com/docs/security/features/apksigning/v2>
///
/// |       Content of ZIP entries      | APK Signing Block |      Central Directory      |     End of Central Directory      |
/// |-----------------------------------|-------------------|-----------------------------|-----------------------------------|
/// | `start_content` -> `stop_content` |                   | `start_cd`   ->   `stop_cd` | `start_eocd`    ->    `stop_eocd` |
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
    pub const fn new(
        stop_content: usize,
        start_cd: usize,
        stop_cd: usize,
        stop_eocd: usize,
    ) -> Self {
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
    pub const fn without_signature(stop_content: usize, stop_cd: usize, stop_eocd: usize) -> Self {
        Self::new(stop_content, stop_content, stop_cd, stop_eocd)
    }
}
