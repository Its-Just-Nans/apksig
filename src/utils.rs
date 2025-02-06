//! # Utils

use std::fmt::LowerHex;

/// macro to add space
macro_rules! add_space {
    ($n:expr) => {
        for _ in 0..$n {
            #[cfg(feature = "directprint")]
            print!(" ");
        }
    };
}
pub(crate) use add_space;

/// macro to print a string
macro_rules! print_string {
    ($fmt:expr) => {
        #[cfg(feature = "directprint")]
        println!($fmt);
    };
    // n args
    ($fmt:expr, $($arg:tt)*) => {
        #[cfg(feature = "directprint")]
        println!($fmt, $($arg)*);
    };
}
pub(crate) use print_string;

use crate::signing_block::VERITY_PADDING_BLOCK_ID;
use crate::SIGNATURE_SCHEME_V2_BLOCK_ID;
use crate::SIGNATURE_SCHEME_V3_BLOCK_ID;

/// Print a hex string up to 20 bytes
pub(crate) fn print_hexe(type_name: &str, data: &[u8]) {
    if cfg!(feature = "directprint") {
        if data.len() > 20 {
            match data.get(..20) {
                Some(_data) => {
                    print_string!("{}: {}..", type_name, to_hexe(_data));
                }
                None => {
                    print_string!("{}: {}..", type_name, to_hexe(data));
                }
            }
        } else {
            print_string!("{}: {}", type_name, to_hexe(data));
        }
    } else {
        let _a = (type_name, data);
    }
}

#[cfg(feature = "directprint")]
/// Convert a slice of bytes to a hex string
pub(crate) fn to_hexe(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{:02x}", b).to_string())
        .collect::<Vec<String>>()
        .join("")
}

/// Magic number decoder
#[derive(Debug, PartialEq)]
pub enum MagicNumberDecoder {
    /// Normal u32
    Normal(u32),
    // Algorithms(Algorithms),
}

impl std::fmt::Display for MagicNumberDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            // Self::Algorithms(algo) => &algo.to_string(),
            Self::Normal(num) => match *num {
                // https://android.googlesource.com/platform/tools/apksig/+/master/src/main/java/com/android/apksig/internal/apk/ApkSigningBlockUtils.java
                VERITY_PADDING_BLOCK_ID => "VERITY_PADDING_BLOCK_ID",
                // https://android.googlesource.com/platform/frameworks/base/+/master/core/java/android/util/apk/SourceStampVerifier.java
                0x6dff800d => "SOURCE_STAMP_BLOCK_ID",
                // https://android.googlesource.com/platform/frameworks/base/+/master/core/java/android/util/apk/SourceStampVerifier.java
                0x9d6303f7 => "PROOF_OF_ROTATION_ATTR_ID",
                SIGNATURE_SCHEME_V2_BLOCK_ID => "Signature Scheme V2",
                SIGNATURE_SCHEME_V3_BLOCK_ID => "Signature Scheme V3",
                _ => "Unknown",
            },
        };
        write!(f, "({:#x}, {})", self, str)
    }
}

impl LowerHex for MagicNumberDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Normal(num) => write!(f, "{:#x}", num),
            // Self::Algorithms(algo) => write!(f, "{:#x}", u32::from(algo)),
        }
    }
}

/// Reader
#[derive(Debug)]
pub struct MyReader {
    /// Data
    data: Vec<u8>,
    /// Position
    pos: usize,
}

impl MyReader {
    /// Create a new reader
    pub fn new(data: &[u8]) -> Self {
        MyReader {
            data: data.to_vec(),
            pos: 0,
        }
    }

    /// Get the length of the data
    pub(crate) fn len(&self) -> usize {
        self.data.len()
    }

    /// Get the current position
    pub(crate) fn get_pos(&self) -> usize {
        self.pos
    }

    /// Get the data as a vector
    pub(crate) fn to_vec(&self) -> Vec<u8> {
        self.data.clone()
    }

    /// Get the data as a slice
    /// # Errors
    /// Returns a string if the parsing fails.
    pub(crate) fn get_to(&mut self, len: usize) -> Result<&[u8], String> {
        let pos = self.pos;
        self.pos += len;
        match self.data.get(pos..self.pos) {
            Some(data) => Ok(data),
            None => {
                if cfg!(feature = "traceback") {
                    Err(format!(
                        "Error: out of bounds {}..{}\n{}",
                        pos,
                        self.pos,
                        std::backtrace::Backtrace::force_capture()
                    ))
                } else {
                    Err(format!("Error: out of bounds: {}..{}", pos, self.pos))
                }
            }
        }
    }

    /// Get the data as a slice
    /// # Errors
    /// Returns a string if the parsing fails.
    pub(crate) fn as_slice(&mut self, end: usize) -> Result<Self, String> {
        Ok(Self {
            data: self.get_to(end)?.to_vec(),
            pos: 0,
        })
    }

    /// Read a u32 as size
    /// # Errors
    /// Returns a string if the parsing fails.
    pub(crate) fn read_size(&mut self) -> Result<usize, String> {
        let temp = self.read_u32()?;
        Ok(temp as usize)
    }

    /// Read a u32
    /// # Errors
    /// Returns a string if the parsing fails.
    pub(crate) fn read_u32(&mut self) -> Result<u32, String> {
        let buf = match self.data.get(self.pos..self.pos + 4) {
            Some(buf) => {
                let mut buffer = [0; 4];
                buffer.copy_from_slice(buf);
                buffer
            }
            None => {
                if cfg!(feature = "traceback") {
                    return Err(format!(
                        "Error: out of bounds reading u32\n{}",
                        std::backtrace::Backtrace::force_capture()
                    ));
                } else {
                    return Err("Error: out of bounds reading u32".to_string());
                }
            }
        };
        self.pos += 4;
        Ok(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]))
    }

    /// Read a u64
    /// # Errors
    /// Returns a string if the parsing fails.
    pub(crate) fn read_u64(&mut self) -> Result<u64, String> {
        let buf = match self.data.get(self.pos..self.pos + 8) {
            Some(buf) => {
                let mut buffer = [0; 8];
                buffer.copy_from_slice(buf);
                buffer
            }
            None => {
                if cfg!(feature = "traceback") {
                    return Err(format!(
                        "Error: out of bounds reading u64\n{}",
                        std::backtrace::Backtrace::force_capture()
                    ));
                } else {
                    return Err("Error: out of bounds reading u64".to_string());
                }
            }
        };
        self.pos += 8;
        Ok(u64::from_le_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ]))
    }

    /// Read a u64 as size
    /// # Errors
    /// Returns a string if the parsing fails.
    pub(crate) fn read_size_u64(&mut self) -> Result<usize, String> {
        let temp = self.read_u64()?;
        Ok(temp as usize)
    }
}

/// Create a fixed buffer of 8 bytes
pub(crate) fn create_fixed_buffer_8(buf: &[u8]) -> [u8; 8] {
    let mut buffer = [0; 8];
    buffer.copy_from_slice(buf);
    buffer
}
