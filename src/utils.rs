//! macro to add space
macro_rules! add_space {
    ($n:expr) => {
        for _ in 0..$n {
            print!(" ");
        }
    };
}
use std::io::Read;

pub(crate) use add_space;

pub const MAGIC: &[u8; 16] = b"APK Sig Block 42";
pub const MAGIC_LEN: i64 = MAGIC.len() as i64;
pub const VERITY_PADDING_BLOCK_ID: u32 = 0x42726577;
pub const SIGNATURE_SCHEME_V2_BLOCK_ID: u32 = 0x7109871a;
pub const SIGNATURE_SCHEME_V3_BLOCK_ID: u32 = 0xf05368c0;

pub(crate) fn to_hexe(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{:02x}", b).to_string())
        .collect::<Vec<String>>()
        .join("")
}

pub struct MagicNumberDecoder(pub u32);

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
            VERITY_PADDING_BLOCK_ID => "VERITY_PADDING_BLOCK_ID",
            // https://android.googlesource.com/platform/frameworks/base/+/master/core/java/android/util/apk/SourceStampVerifier.java
            0x6dff800d => "SOURCE_STAMP_BLOCK_ID",
            // https://android.googlesource.com/platform/frameworks/base/+/master/core/java/android/util/apk/SourceStampVerifier.java
            0x9d6303f7 => "PROOF_OF_ROTATION_ATTR_ID",
            SIGNATURE_SCHEME_V2_BLOCK_ID => "Signature Scheme V2",
            SIGNATURE_SCHEME_V3_BLOCK_ID => "Signature Scheme V3",
            _ => "Unknown",
        };
        write!(f, "({:#x}, {})", self.0, str)
    }
}

pub(crate) struct MyReader {
    data: Vec<u8>,
    pos: usize,
}

impl MyReader {
    pub(crate) fn new(data: &[u8]) -> Self {
        MyReader {
            data: data.to_vec(),
            pos: 0,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.data.len()
    }

    pub(crate) fn get_pos(&self) -> usize {
        self.pos
    }

    pub(crate) fn to_vec(&self) -> Vec<u8> {
        self.data.clone()
    }

    pub(crate) fn get_to(&mut self, len: usize) -> &[u8] {
        let pos = self.pos;
        self.pos += len;
        &self.data[pos..self.pos]
    }

    pub(crate) fn as_slice(&mut self, end: usize) -> Self {
        let pos = self.pos;
        self.pos += end;
        MyReader {
            data: self.data[pos..self.pos].to_vec(),
            pos: 0,
        }
    }

    pub(crate) fn read_size(&mut self) -> usize {
        self.read_u32() as usize
    }

    pub(crate) fn read_u32(&mut self) -> u32 {
        let mut buf = [0; 4];
        buf.copy_from_slice(&self.data[self.pos..self.pos + 4]);
        self.pos += 4;
        u32::from_le_bytes(buf)
    }
    pub(crate) fn read_u64(&mut self) -> u64 {
        let mut buf = [0; 8];
        buf.copy_from_slice(&self.data[self.pos..self.pos + 8]);
        self.pos += 8;
        u64::from_le_bytes(buf)
    }

    pub(crate) fn read_size_u64(&mut self) -> usize {
        self.read_u64() as usize
    }
}

impl Read for MyReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let len = std::cmp::min(buf.len(), self.data.len() - self.pos);
        buf[..len].copy_from_slice(&self.data[self.pos..self.pos + len]);
        self.pos += len;
        Ok(len)
    }
}
