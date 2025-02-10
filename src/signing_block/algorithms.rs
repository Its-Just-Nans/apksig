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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let sig = u32::deserialize(deserializer)?;
        Ok(Self::from(sig))
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

    /// Verify signature
    /// # Arguments
    /// * `pubkey` - Public key from the signing block
    /// * `raw_data` - Raw data from the signed_data (without the 4 bytes of size) of the signing block
    /// * `signature` - Signature from the signing block
    /// # Errors
    /// Returns an error if the signature is invalid
    #[cfg(feature = "signing")]
    pub fn verify(&self, pubkey: &[u8], raw_data: &[u8], signature: &[u8]) -> Result<(), String> {
        use rsa::pkcs8::DecodePublicKey;
        use rsa::sha2::{Sha256, Sha512};
        use rsa::{Pkcs1v15Sign, RsaPublicKey};
        let key = match RsaPublicKey::from_public_key_der(pubkey) {
            Ok(key) => key,
            Err(_) => return Err("Invalid public key".to_string()),
        };
        let data = self.hash(raw_data);
        match &self {
            Self::RSASSA_PKCS1_v1_5_256 => {
                let pkcs = Pkcs1v15Sign::new::<Sha256>();
                match key.verify(pkcs, &data, signature) {
                    Ok(_) => Ok(()),
                    Err(_) => Err("Invalid signature".to_string()),
                }
            }
            Self::RSASSA_PKCS1_v1_5_512 => {
                let pkcs = Pkcs1v15Sign::new::<Sha512>();
                match key.verify(pkcs, &data, signature) {
                    Ok(_) => Ok(()),
                    Err(_) => Err("Invalid signature".to_string()),
                }
            }
            Self::RSASSA_PSS_256 => {
                let pkcs = rsa::pss::Pss::new::<Sha256>();
                match key.verify(pkcs, &data, signature) {
                    Ok(_) => Ok(()),
                    Err(_) => Err("Invalid signature".to_string()),
                }
            }
            Self::RSASSA_PSS_512 => {
                let pkcs = rsa::pss::Pss::new::<Sha512>();
                match key.verify(pkcs, &data, signature) {
                    Ok(_) => Ok(()),
                    Err(_) => Err("Invalid signature".to_string()),
                }
            }
            _ => Err("Not implemented".to_string()),
        }
    }

    /// Sign data
    /// # Errors
    /// Returns a string if the signing fails.
    #[cfg(feature = "signing")]
    pub fn sign(
        &self,
        private_key: rsa::RsaPrivateKey,
        raw_data: &[u8],
    ) -> Result<Vec<u8>, String> {
        let hashed = &self.hash(raw_data);
        match &self {
            Self::RSASSA_PKCS1_v1_5_256 => {
                use rsa::sha2::Sha256;
                use rsa::Pkcs1v15Sign;
                let pkcs = Pkcs1v15Sign::new::<Sha256>();
                private_key.sign(pkcs, hashed).map_err(|e| e.to_string())
            }
            Self::RSASSA_PKCS1_v1_5_512 => {
                use rsa::sha2::Sha512;
                use rsa::Pkcs1v15Sign;
                let pkcs = Pkcs1v15Sign::new::<Sha512>();
                private_key.sign(pkcs, hashed).map_err(|e| e.to_string())
            }
            Self::RSASSA_PSS_256 => {
                use rsa::pss::Pss;
                use rsa::sha2::Sha256;
                let pkcs = Pss::new::<Sha256>();
                private_key.sign(pkcs, hashed).map_err(|e| e.to_string())
            }
            Self::RSASSA_PSS_512 => {
                use rsa::pss::Pss;
                use rsa::sha2::Sha512;
                let pkcs = Pss::new::<Sha512>();
                private_key.sign(pkcs, hashed).map_err(|e| e.to_string())
            }
            _ => Err("Not implemented".to_string()),
        }
    }
}
