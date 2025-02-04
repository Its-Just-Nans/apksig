//! Module for the APK Signing Block
//! https://source.android.com/docs/security/features/apksigning

use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::mem;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub mod scheme_v2;
pub mod scheme_v3;

#[cfg(feature = "directprint")]
use crate::utils::MagicNumberDecoder;

use crate::utils::print_string;
use crate::utils::{add_space, MyReader};
use scheme_v2::SignatureSchemeV2;
use scheme_v2::SIGNATURE_SCHEME_V2_BLOCK_ID;
use scheme_v3::SignatureSchemeV3;
use scheme_v3::SIGNATURE_SCHEME_V3_BLOCK_ID;

/// Magic number of the APK Signing Block
pub const MAGIC: &[u8; 16] = b"APK Sig Block 42";

/// Length of the magic number
pub const MAGIC_LEN: usize = MAGIC.len();

/// Size of a u64
pub const VERITY_PADDING_BLOCK_ID: u32 = 0x42726577;

/// Size of a u64
const SIZE_UINT64: usize = mem::size_of::<u64>();

/// Raw data extracted from the APK Signing Block
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RawData {
    /// Size of the data
    /// u64
    pub size: usize,

    /// ID of the data
    pub id: u32,

    /// Data
    pub data: Vec<u8>,
}

impl RawData {
    /// Create a new RawData
    pub fn new(id: u32, data: Vec<u8>) -> Self {
        let size = mem::size_of::<u32>() + data.len();
        Self { size, id, data }
    }

    /// Serialize to u8
    fn to_u8(&self) -> Vec<u8> {
        [
            (self.size as u64).to_le_bytes()[..].to_vec(),
            self.id.to_le_bytes()[..].to_vec(),
            self.data.to_vec(),
        ]
        .concat()
    }
}

/// Value of the APK Signing Block
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ValueSigningBlock {
    /// Base Signing Block
    BaseSigningBlock(RawData),

    /// Signature Scheme V2
    SignatureSchemeV2Block(SignatureSchemeV2),

    /// Signature Scheme V3
    SignatureSchemeV3Block(SignatureSchemeV3),
}

impl ValueSigningBlock {
    /// Parse the value
    /// # Errors
    /// Returns a string if the parsing fails.
    pub fn parse(data: &mut MyReader) -> Result<Self, String> {
        let pair_size = data.read_size_u64()?;
        print_string!("Pair size: {} bytes", pair_size);

        let pair_id = data.read_u32()?;
        print_string!("Pair ID: {} {}", pair_id, MagicNumberDecoder(pair_id));

        let value_length = match pair_size.checked_sub(4) {
            Some(v) => v,
            None => {
                return Err(format!(
                    "Error: pair_size {} is less than 4 (pair_id size)",
                    pair_size
                ));
            }
        };
        let block_value = &mut data.as_slice(value_length)?;

        print_string!("Pair Content:");
        let block_to_add = match pair_id {
            SIGNATURE_SCHEME_V2_BLOCK_ID => ValueSigningBlock::SignatureSchemeV2Block(
                SignatureSchemeV2::parse(pair_size, pair_id, block_value)?,
            ),
            SIGNATURE_SCHEME_V3_BLOCK_ID => ValueSigningBlock::SignatureSchemeV3Block(
                SignatureSchemeV3::parse(pair_size, pair_id, block_value)?,
            ),
            VERITY_PADDING_BLOCK_ID => {
                add_space!(4);
                print_string!("Padding Block of {} bytes", block_value.len());
                ValueSigningBlock::BaseSigningBlock(RawData {
                    size: pair_size,
                    id: pair_id,
                    data: block_value.to_vec(),
                })
            }
            _ => ValueSigningBlock::BaseSigningBlock(RawData {
                size: pair_size,
                id: pair_id,
                data: block_value.to_vec(),
            }),
        };
        Ok(block_to_add)
    }

    /// Serialize to u8
    pub fn to_u8(&self) -> Vec<u8> {
        match self {
            ValueSigningBlock::SignatureSchemeV2Block(scheme) => scheme.to_u8(),
            ValueSigningBlock::SignatureSchemeV3Block(scheme) => scheme.to_u8(),
            ValueSigningBlock::BaseSigningBlock(block) => block.to_u8(),
        }
    }
}

/// APK Signing Block
#[derive(Debug, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SigningBlock {
    /// Offset of the start of the block in the file
    pub file_offset_start: usize,

    /// Offset of the end of the block in the file
    pub file_offset_end: usize,

    /// Size of block - at the start of the block
    pub size_of_block_start: usize,

    /// content_size
    pub content_size: usize,

    /// Content of the block
    pub content: Vec<ValueSigningBlock>,

    /// Size of block - at the end of the block
    pub size_of_block_end: usize,

    /// Magic string
    pub magic: [u8; 16],
}

impl SigningBlock {
    /// Extract the APK Signing Block from the APK file
    /// # Errors
    /// Return an error appends during decoding
    pub fn from_reader<R: Read + Seek>(
        mut reader: R,
        file_len: usize,
        end_offset: usize,
    ) -> Result<Self, std::io::Error> {
        let start_loop = end_offset + MAGIC_LEN;
        for idx in start_loop..file_len {
            reader.seek(SeekFrom::End(-(idx as i64)))?;
            let mut magic_buf = [0; MAGIC_LEN];
            match reader.read_exact(&mut magic_buf) {
                Ok(_) => {
                    if &magic_buf == MAGIC {
                        let pos_end_block_size = idx + SIZE_UINT64;
                        reader.seek(SeekFrom::End(-(pos_end_block_size as i64)))?;
                        let mut buf = [0; SIZE_UINT64];
                        reader.read_exact(&mut buf)?;
                        let block_size = u64::from_le_bytes(buf) as usize;
                        let file_offset_start = match (file_len - idx + MAGIC_LEN)
                            .checked_sub(block_size + SIZE_UINT64)
                        {
                            Some(v) => v,
                            None => {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::Other,
                                    format!(
                                        "Error: starting at {} is less than {} (block size + size of u64)",
                                        file_len - idx + MAGIC_LEN, block_size + SIZE_UINT64
                                    ),
                                ));
                            }
                        };
                        let mut vec_full_block = vec![0; block_size + SIZE_UINT64];
                        reader.seek(SeekFrom::Start(file_offset_start as u64))?;
                        reader.read_exact(&mut vec_full_block)?;
                        let file_offset_end = file_offset_start + SIZE_UINT64 + block_size;
                        print_string!("--- Start of Signature Block ---");
                        let mut sig = match Self::parse_full_block(&vec_full_block) {
                            Ok(v) => v,
                            Err(e) => {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::Other,
                                    format!("Error parsing full block: {}", e),
                                ));
                            }
                        };
                        sig.file_offset_start = file_offset_start;
                        sig.file_offset_end = file_offset_end;
                        print_string!("--- End of Signature Block ---");
                        return Ok(sig);
                    }
                }
                Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Error reading file, {}", file_len - idx),
                    ));
                }
            }
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "from_reader(): Magic not found\nMAGIC is '{:?}' (as [u8]) or '{}' (as string)",
                MAGIC,
                String::from_utf8_lossy(MAGIC)
            ),
        ))
    }

    /// Parse the APK Signing Block from a byte array
    /// # Errors
    /// Return an error appends during decoding
    fn parse_full_block(data: &[u8]) -> Result<Self, String> {
        if data.len() < SIZE_UINT64 + SIZE_UINT64 + MAGIC_LEN {
            return Err(format!(
                "Error: data length {} is less than {} (size of u64 + size of u64 + size of magic number)",
                data.len(),
                SIZE_UINT64 + SIZE_UINT64 + MAGIC_LEN
            ));
        }
        let magic = data[data.len() - MAGIC_LEN..data.len()].to_vec();
        if magic != MAGIC {
            return Err(format!(
                "parse_full_block(): Magic not found\nMAGIC is '{:?}' (as [u8]) or '{}' (as string)",
                MAGIC,
                String::from_utf8_lossy(MAGIC)
            ));
        }
        let start_block_size = u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]) as usize;
        let end_size =
            data[(data.len() - MAGIC_LEN - SIZE_UINT64)..data.len() - MAGIC_LEN].to_vec();
        let end_block_size = u64::from_le_bytes([
            end_size[0],
            end_size[1],
            end_size[2],
            end_size[3],
            end_size[4],
            end_size[5],
            end_size[6],
            end_size[7],
        ]) as usize;
        debug_assert_eq!(start_block_size, end_block_size);
        if start_block_size != end_block_size {
            return Err(format!(
                "Error: start_block_size {} is different from end_block_size {}",
                start_block_size, end_block_size
            ));
        }
        let content_size = end_block_size - SIZE_UINT64 - MAGIC_LEN;
        let content = match SigningBlock::extract_values(&mut MyReader::new(
            &data[8..data.len() - MAGIC_LEN - SIZE_UINT64],
        )) {
            Ok(v) => v,
            Err(e) => {
                return Err(format!("Error extracting values: {}", e));
            }
        };
        Ok(Self {
            magic: MAGIC.to_owned(),
            file_offset_start: 0,
            file_offset_end: data.len(),
            content_size,
            content,
            size_of_block_end: end_block_size,
            size_of_block_start: start_block_size,
        })
    }

    /// Extract the APK Signing Block from the APK file
    /// # Errors
    /// Return an error appends during decoding
    pub fn from_u8(data: &[u8]) -> Result<Self, String> {
        if data.len() < SIZE_UINT64 + SIZE_UINT64 + MAGIC_LEN {
            return Err(format!(
                "Error: data length {} is less than {} (size of magic number)",
                data.len(),
                MAGIC_LEN
            ));
        }
        for idx in MAGIC_LEN..data.len() {
            let start_magic = data.len() - idx;
            let end_magic = start_magic + MAGIC_LEN;
            if &data[start_magic..end_magic] == MAGIC {
                let size = u64::from_le_bytes([
                    data[start_magic - SIZE_UINT64],
                    data[start_magic - SIZE_UINT64 + 1],
                    data[start_magic - SIZE_UINT64 + 2],
                    data[start_magic - SIZE_UINT64 + 3],
                    data[start_magic - SIZE_UINT64 + 4],
                    data[start_magic - SIZE_UINT64 + 5],
                    data[start_magic - SIZE_UINT64 + 6],
                    data[start_magic - SIZE_UINT64 + 7],
                ]) as usize;
                let start_full_block = match start_magic.checked_sub(size - MAGIC_LEN + SIZE_UINT64)
                {
                    Some(v) => v,
                    None => {
                        return Err(format!(
                            "Error: start_magic {} is less than {} (size of u64)",
                            start_magic, SIZE_UINT64
                        ));
                    }
                };
                let sig = Self::parse_full_block(&data[start_full_block..end_magic])?;
                return Ok(sig);
            }
        }
        Err(format!(
            "from_u8(): Magic not found\nMAGIC is '{:?}' (as [u8]) or '{}' (as string)",
            MAGIC,
            String::from_utf8_lossy(MAGIC)
        ))
    }

    /// Extract the values from the APK Signing Block
    /// # Errors
    /// Return an error appends during decoding
    fn extract_values(data: &mut MyReader) -> Result<Vec<ValueSigningBlock>, String> {
        let mut blocks = Vec::new();
        while data.get_pos() < data.len() {
            blocks.push(ValueSigningBlock::parse(data)?);
        }
        Ok(blocks)
    }

    /// Serialize to u8 the content
    pub fn content_to_u8(&self) -> Vec<u8> {
        self.content
            .iter()
            .flat_map(|b| b.to_u8())
            .collect::<Vec<u8>>()
    }

    /// Serialize to u8
    pub fn to_u8(&self) -> Vec<u8> {
        [
            (self.size_of_block_start as u64).to_le_bytes()[..].to_vec(),
            self.content_to_u8(),
            (self.size_of_block_end as u64).to_le_bytes()[..].to_vec(),
            self.magic.to_vec(),
        ]
        .concat()
    }
}
