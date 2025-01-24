use std::fs;
use std::io::Read;
use std::io::Seek;
use std::io::{BufReader, SeekFrom};

mod scheme_v2;
mod scheme_v3;
mod utils;

use utils::{add_space, to_hexe, MagicNumberDecoder, MyReader};
pub use utils::{
    MAGIC, MAGIC_LEN, SIGNATURE_SCHEME_V2_BLOCK_ID, SIGNATURE_SCHEME_V3_BLOCK_ID,
    VERITY_PADDING_BLOCK_ID,
};

pub use scheme_v2::SignatureSchemeV2;
pub use scheme_v3::SignatureSchemeV3;

#[derive(Debug)]
pub struct RawData {
    pub size: usize,
    pub id: u32,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub enum ValueSigningBlock {
    BaseSigningBlock(RawData),
    SignatureSchemeV2Block(SignatureSchemeV2),
    SignatureSchemeV3Block(SignatureSchemeV3),
}

#[derive(Debug, Default)]
pub struct SigningBlock {
    pub offset_start: usize,
    pub offset_end: usize,
    pub start_size: usize,
    pub content_size: usize,
    pub content: Vec<ValueSigningBlock>,
    pub end_size: usize,
    pub magic: [u8; 16],
}

impl SigningBlock {
    pub fn extract<R: Read + Seek>(
        mut reader: R,
        file_len: usize,
        end_offset: usize,
    ) -> Result<Self, std::io::Error> {
        let start_loop = end_offset + MAGIC_LEN;
        for idx in start_loop..file_len {
            reader.seek(SeekFrom::End(-(idx as i64)))?;
            let mut buf = [0; MAGIC_LEN];
            match reader.read_exact(&mut buf) {
                Ok(_) => {
                    if &buf == MAGIC {
                        let mut sig_block = SigningBlock {
                            magic: buf,
                            ..Default::default()
                        };
                        const SIZE_UINT64: usize = 8;
                        let pos_block_size = idx + SIZE_UINT64;
                        reader.seek(SeekFrom::End(-(pos_block_size as i64)))?;
                        let mut buf = [0; SIZE_UINT64];
                        reader.read_exact(&mut buf)?;
                        let block_size = u64::from_le_bytes(buf) as usize;
                        sig_block.end_size = block_size;
                        let inner_block_size = block_size - SIZE_UINT64 - MAGIC_LEN;
                        let full_block = pos_block_size + inner_block_size;
                        let mut vec: Vec<u8> = vec![0; inner_block_size];
                        reader.seek(SeekFrom::End(-(full_block as i64)))?;
                        reader.read_exact(&mut vec)?;
                        sig_block.content = SigningBlock::extract_values(&mut MyReader::new(&vec));
                        let start_block_size = full_block + SIZE_UINT64;
                        reader.seek(SeekFrom::End(-(start_block_size as i64)))?;
                        sig_block.offset_start = file_len - start_block_size;
                        sig_block.offset_end = file_len - idx + MAGIC_LEN;
                        sig_block.content_size = inner_block_size;
                        let mut buf = [0; SIZE_UINT64];
                        reader.read_exact(&mut buf).unwrap();
                        let start_block_size = u64::from_le_bytes(buf) as usize;
                        sig_block.start_size = start_block_size;
                        assert_eq!(sig_block.start_size, sig_block.end_size);
                        return Ok(sig_block);
                    }
                }
                Err(_) => {
                    println!("Error reading file, {}", file_len - idx);
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Error reading file",
                    ));
                }
            }
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "Magic not found\n MAGIC is '{:?}' (binary) and '{}' (string)",
                MAGIC,
                String::from_utf8_lossy(MAGIC)
            ),
        ))
    }

    fn extract_values(data: &mut MyReader) -> Vec<ValueSigningBlock> {
        // println!("Extracting values from {:?}", data);
        let mut blocks = Vec::new();
        while data.get_pos() < data.len() {
            let pair_size = data.read_size_u64();
            println!("Pair size: {} bytes", pair_size);

            let pair_id = data.read_u32();
            println!("Pair ID: {} {}", pair_id, MagicNumberDecoder(pair_id));

            let value_length = pair_size - 4;
            let block_value = &mut data.as_slice(value_length);

            println!("Pair Content:");
            let block_to_add = match pair_id {
                SIGNATURE_SCHEME_V2_BLOCK_ID => ValueSigningBlock::SignatureSchemeV2Block(
                    SignatureSchemeV2::new(pair_size, pair_id, block_value),
                ),
                SIGNATURE_SCHEME_V3_BLOCK_ID => ValueSigningBlock::SignatureSchemeV3Block(
                    SignatureSchemeV3::new(pair_size, pair_id, block_value),
                ),
                VERITY_PADDING_BLOCK_ID => {
                    add_space!(4);
                    println!("Padding Block of {} bytes", block_value.len());
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
            blocks.push(block_to_add);
        }
        blocks
    }
}

pub fn real_main() -> Result<i32, Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} <filename>", args[0]);
        return Ok(1);
    }
    let fname = std::path::Path::new(&args[1]);
    let file = fs::File::open(fname)?;
    let mut reader = BufReader::new(file);

    let file_len = reader.seek(std::io::SeekFrom::End(0))? as usize;
    println!("{} length: {} bytes", fname.display(), file_len);
    // find the magic string starting from the end of the file
    let sig_block = SigningBlock::extract(reader, file_len, 0)?;
    println!();
    println!(
        "APK Signing Block is between {} and {} with a size of {} bytes",
        sig_block.offset_start,
        sig_block.offset_end,
        sig_block.start_size + 8
    );
    Ok(0)
}
