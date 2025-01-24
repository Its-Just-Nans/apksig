use std::fs;
use std::io::Read;
use std::io::Seek;
use std::io::{BufReader, SeekFrom};

mod scheme_v2;

use scheme_v2::SignatureSchemeV2Block;

const MAGIC: &[u8; 16] = b"APK Sig Block 42";
const MAGIC_LEN: i64 = MAGIC.len() as i64;

pub fn read_u32(data: &[u8]) -> u32 {
    let mut buf = [0; 4];
    buf.copy_from_slice(&data[..4]);
    u32::from_le_bytes(buf)
}

pub fn read_u64(data: &[u8]) -> u64 {
    let mut buf = [0; 8];
    buf.copy_from_slice(&data[..8]);
    u64::from_le_bytes(buf)
}

#[derive(Debug)]
struct RawData {
    size: u64,
    id: u32,
    data: Vec<u8>,
}

#[derive(Debug)]
struct SignatureSchemeV3Block {
    size: u64,
    id: u32,
    data: Vec<u8>,
}

#[derive(Debug)]
enum ValueSigningBlock {
    BaseSigningBlock(RawData),
    SignatureSchemeV2Block(SignatureSchemeV2Block),
    SignatureSchemeV3Block(SignatureSchemeV3Block),
}

#[derive(Debug, Default)]
struct SigningBlock {
    start_size: u64,
    content: Vec<ValueSigningBlock>,
    end_size: u64,
    magic: [u8; 16],
}

struct MagicNumberDecoder(u32);

impl std::fmt::Display for MagicNumberDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self.0 {
            0x0101 => "RSASSA-PSS with SHA2-256 digest, SHA2-256 MGF1, 32 bytes of salt, trailer: 0xbc",
            0x0102 => "RSASSA-PSS with SHA2-512 digest, SHA2-512 MGF1, 64 bytes of salt, trailer: 0xbc",
            0x0103 => "RSASSA-PKCS1-v1_5 with SHA2-256 digest. This is for build systems which require deterministic signatures.",
            0x0104 => "RSASSA-PKCS1-v1_5 with SHA2-512 digest. This is for build systems which require deterministic signatures.",
            0x0201 => "ECDSA with SHA2-256 digest",
            0x0202 => "ECDSA with SHA2-512 digest",
            0x0301 => "DSA with SHA2-256 digest",
            // https://android.googlesource.com/platform/tools/apksig/+/master/src/main/java/com/android/apksig/internal/apk/ApkSigningBlockUtils.java
            0x42726577 => "VERITY_PADDING_BLOCK_ID",
            // https://android.googlesource.com/platform/frameworks/base/+/master/core/java/android/util/apk/SourceStampVerifier.java
            0x6dff800d => "SOURCE_STAMP_BLOCK_ID",
            // https://android.googlesource.com/platform/frameworks/base/+/master/core/java/android/util/apk/SourceStampVerifier.java
            0x9d6303f7 => "PROOF_OF_ROTATION_ATTR_ID",
            SIGNATURE_SCHEME_V2_BLOCK_ID => "SignatureSchemeV2Block",
            SIGNATURE_SCHEME_V3_BLOCK_ID => "SignatureSchemeV3Block",
            _ => "Unknown",
        };
        write!(f, "({:#x}, {})", self.0, str)
    }
}

const SIGNATURE_SCHEME_V2_BLOCK_ID: u32 = 0x7109871a;
const SIGNATURE_SCHEME_V3_BLOCK_ID: u32 = 0xf05368c0;

impl SigningBlock {
    fn extract<R: Read + Seek>(mut reader: R, file_len: u64, end_offset: u64) -> Self {
        let file_len = file_len as i64;
        let start_loop = (end_offset as i64) + MAGIC_LEN;
        let mut sig_block = SigningBlock::default();
        for i in start_loop..file_len {
            reader.seek(SeekFrom::End(-i)).unwrap();
            let mut buf = [0; MAGIC_LEN as usize];
            match reader.read_exact(&mut buf) {
                Ok(_) => {
                    if &buf == MAGIC {
                        sig_block.magic = buf;
                        const SIZE_UINT64: i64 = 8;
                        let pos_block_size = i + SIZE_UINT64;
                        reader.seek(SeekFrom::End(-pos_block_size)).unwrap();
                        let mut buf = [0; SIZE_UINT64 as usize];
                        reader.read_exact(&mut buf).unwrap();
                        let block_size = u64::from_le_bytes(buf);
                        sig_block.end_size = block_size;
                        let inner_block_size = block_size - SIZE_UINT64 as u64 - MAGIC_LEN as u64;
                        let full_block = pos_block_size + inner_block_size as i64;
                        let mut vec: Vec<u8> = vec![0; inner_block_size as usize];
                        reader.seek(SeekFrom::End(-full_block)).unwrap();
                        reader.read_exact(&mut vec).unwrap();
                        sig_block.content = SigningBlock::extract_values(&vec);
                        let start_block_size = full_block + SIZE_UINT64;
                        reader.seek(SeekFrom::End(-start_block_size)).unwrap();
                        let mut buf = [0; SIZE_UINT64 as usize];
                        reader.read_exact(&mut buf).unwrap();
                        let start_block_size = u64::from_le_bytes(buf);
                        sig_block.start_size = start_block_size;
                        break;
                    }
                }
                Err(_) => {
                    println!("Error reading file, {}", i);
                    break;
                }
            }
        }
        assert_eq!(sig_block.start_size, sig_block.end_size);
        sig_block
    }

    fn extract_values(data: &[u8]) -> Vec<ValueSigningBlock> {
        // println!("Extracting values from {:?}", data);
        let mut blocks = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            println!("Position: {}/{}", pos, data.len());
            let mut buf_size = [0; 8];
            buf_size.copy_from_slice(&data[pos..pos + 8]);
            pos += 8;
            let block_size = u64::from_le_bytes(buf_size);
            println!("Block size: {}", block_size);

            let mut buf_id = [0; 4];
            buf_id.copy_from_slice(&data[pos..pos + 4]);
            pos += 4;
            let block_id = u32::from_le_bytes(buf_id);
            println!("Block id: {} {}", block_id, MagicNumberDecoder(block_id));

            let value_length = (block_size - 4) as usize;
            let block_value = &data[pos..pos + value_length];
            pos += value_length;

            let block_to_add = match block_id {
                SIGNATURE_SCHEME_V2_BLOCK_ID => ValueSigningBlock::SignatureSchemeV2Block(
                    SignatureSchemeV2Block::new(block_size, block_id, block_value),
                ),
                SIGNATURE_SCHEME_V3_BLOCK_ID => {
                    ValueSigningBlock::SignatureSchemeV3Block(SignatureSchemeV3Block {
                        size: block_size,
                        id: block_id,
                        data: block_value.to_vec(),
                    })
                }
                _ => ValueSigningBlock::BaseSigningBlock(RawData {
                    size: block_size,
                    id: block_id,
                    data: block_value.to_vec(),
                }),
            };
            blocks.push(block_to_add);
        }
        blocks
    }
}

pub fn real_main() -> i32 {
    let args: Vec<_> = std::env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} <filename>", args[0]);
        return 1;
    }
    let fname = std::path::Path::new(&*args[1]);
    let file = fs::File::open(fname).unwrap();
    let mut reader = BufReader::new(file);

    let file_len = reader.seek(std::io::SeekFrom::End(0)).unwrap();
    println!("{} length: {} bytes", fname.display(), file_len);
    // find the magic string starting from the end of the file
    SigningBlock::extract(reader, file_len, 0);
    0
}

fn to_hexe(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{:02x}", b).to_string())
        .collect::<Vec<String>>()
        .join("")
}
