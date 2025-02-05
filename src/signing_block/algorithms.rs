//! Signatures for APK Signing Block

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Id of RSASSA-PSS with SHA2-256 digest, SHA2-256 MGF1, 32 bytes of salt
pub const SIGNATURE_RSA_PSS_256: u32 = 0x0101;
/// Id of RSASSA-PSS with SHA2-512 digest, SHA2-512 MGF1, 64 bytes of salt
pub const SIGNATURE_RSA_PSS_512: u32 = 0x0102;
/// Id of RSASSA-PKCS1-v1_5 with SHA2-256 digest
pub const SIGNATURE_RSA_PKCS1_256: u32 = 0x0103;
/// Id of RSASSA-PKCS1-v1_5 with SHA2-512 digest
pub const SIGNATURE_RSA_PKCS1_512: u32 = 0x0104;
/// Id of ECDSA with SHA2-256 digest
pub const SIGNATURE_ECDSA_256: u32 = 0x0201;
/// Id of ECDSA with SHA2-512 digest
pub const SIGNATURE_ECDSA_512: u32 = 0x0202;
/// Id of DSA with SHA2-256 digest
pub const SIGNATURE_DSA_256: u32 = 0x0301;

/// Signature algorithms
#[derive(Debug, Clone, PartialEq)]
#[allow(non_camel_case_types)]
pub enum Algorithms {
    /// RSASSA-PSS with SHA2-256 digest, SHA2-256 MGF1, 32 bytes of salt
    RSASSA_PSS_256,
    /// RSASSA-PSS with SHA2-512 digest, SHA2-512 MGF1, 64 bytes of salt
    RSASSA_PSS_512,
    /// RSASSA-PKCS1-v1_5 with SHA2-256 digest.
    RSASSA_PKCS1_v1_5_256,
    /// RSASSA-PKCS1-v1_5 with SHA2-512 digest.
    RSASSA_PKCS1_v1_5_512,
    /// ECDSA with SHA2-256 digest
    ECDSA_SHA2_256,
    /// ECDSA with SHA2-512 digest
    ECDSA_SHA2_512,
    /// DSA with SHA2-256 digest
    DSA_SHA2_256,
    /// Unknown algorithm
    Unknown(u32),
}

#[cfg(feature = "serde")]
impl Serialize for Algorithms {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        u32::from(self).serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Algorithms {
    fn deserialize<D>(deserializer: D) -> Result<Algorithms, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let sig = u32::deserialize(deserializer)?;
        Ok(Algorithms::from(sig))
    }
}

impl PartialEq<Algorithms> for u32 {
    fn eq(&self, sig: &Algorithms) -> bool {
        match sig {
            Algorithms::RSASSA_PSS_256 => self == &SIGNATURE_RSA_PSS_256,
            Algorithms::RSASSA_PSS_512 => self == &SIGNATURE_RSA_PSS_512,
            Algorithms::RSASSA_PKCS1_v1_5_256 => self == &SIGNATURE_RSA_PKCS1_256,
            Algorithms::RSASSA_PKCS1_v1_5_512 => self == &SIGNATURE_RSA_PKCS1_512,
            Algorithms::ECDSA_SHA2_256 => self == &SIGNATURE_ECDSA_256,
            Algorithms::ECDSA_SHA2_512 => self == &SIGNATURE_ECDSA_512,
            Algorithms::DSA_SHA2_256 => self == &SIGNATURE_DSA_256,
            Algorithms::Unknown(u) => self == u,
        }
    }
}

impl std::fmt::Display for Algorithms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match *self {
            Self::RSASSA_PSS_256 => "RSASSA-PSS with SHA2-256 digest, SHA2-256 MGF1, 32 bytes of salt, trailer: 0xbc",
            Self::RSASSA_PSS_512 => "RSASSA-PSS with SHA2-512 digest, SHA2-512 MGF1, 64 bytes of salt, trailer: 0xbc",
            Self::RSASSA_PKCS1_v1_5_256 => "RSASSA-PKCS1-v1_5 with SHA2-256 digest. This is for build systems which require deterministic signatures.",
            Self::RSASSA_PKCS1_v1_5_512 => "RSASSA-PKCS1-v1_5 with SHA2-512 digest. This is for build systems which require deterministic signatures.",
            Self::ECDSA_SHA2_256 => "ECDSA with SHA2-256 digest",
            Self::ECDSA_SHA2_512 => "ECDSA with SHA2-512 digest",
            Self::DSA_SHA2_256 => "DSA with SHA2-256 digest",
            Self::Unknown(u) => &format!("Unknown algorithm: 0x{:04x}", u),
        };
        write!(f, "{:#x} - {}", u32::from(self), str)
    }
}

impl From<u32> for Algorithms {
    fn from(sig: u32) -> Self {
        match sig {
            SIGNATURE_RSA_PSS_256 => Self::RSASSA_PSS_256,
            SIGNATURE_RSA_PSS_512 => Self::RSASSA_PSS_512,
            SIGNATURE_RSA_PKCS1_256 => Self::RSASSA_PKCS1_v1_5_256,
            SIGNATURE_RSA_PKCS1_512 => Self::RSASSA_PKCS1_v1_5_512,
            SIGNATURE_ECDSA_256 => Self::ECDSA_SHA2_256,
            SIGNATURE_ECDSA_512 => Self::ECDSA_SHA2_512,
            SIGNATURE_DSA_256 => Self::DSA_SHA2_256,
            _ => Self::Unknown(sig),
        }
    }
}

impl From<&Algorithms> for u32 {
    fn from(sig: &Algorithms) -> Self {
        match *sig {
            Algorithms::RSASSA_PSS_256 => SIGNATURE_RSA_PSS_256,
            Algorithms::RSASSA_PSS_512 => SIGNATURE_RSA_PSS_512,
            Algorithms::RSASSA_PKCS1_v1_5_256 => SIGNATURE_RSA_PKCS1_256,
            Algorithms::RSASSA_PKCS1_v1_5_512 => SIGNATURE_RSA_PKCS1_512,
            Algorithms::ECDSA_SHA2_256 => SIGNATURE_ECDSA_256,
            Algorithms::ECDSA_SHA2_512 => SIGNATURE_ECDSA_512,
            Algorithms::DSA_SHA2_256 => SIGNATURE_DSA_256,
            Algorithms::Unknown(u) => u,
        }
    }
}

/// Hashing functions
#[cfg(feature = "hash")]
fn sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Hashing functions
#[cfg(feature = "hash")]
fn sha512(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

impl Algorithms {
    /// Hash data
    #[cfg(feature = "hash")]
    pub fn hash(&self, data: &[u8]) -> Vec<u8> {
        match &self {
            Self::RSASSA_PSS_256
            | Self::RSASSA_PKCS1_v1_5_256
            | Self::ECDSA_SHA2_256
            | Self::DSA_SHA2_256 => sha256(data),
            Self::RSASSA_PSS_512 | Self::RSASSA_PKCS1_v1_5_512 | Self::ECDSA_SHA2_512 => {
                sha512(data)
            }
            Self::Unknown(_) => Vec::new(),
        }
    }
}
