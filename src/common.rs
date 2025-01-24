//! # Common types for scheme

/// The `Digest` struct represents the digest of the signed data.
#[derive(Debug)]
pub struct Digest {
    /// The signature algorithm ID of the digest.
    pub signature_algorithm_id: u32,

    /// The digest of the signed data.
    pub digest: Vec<u8>,
}

/// The `Certificate` struct represents the certificate of the signed data.
#[derive(Debug)]
pub struct Certificate {
    /// The certificate of the signed data.
    pub certificate: Vec<u8>,
}

/// The `Signatures` struct represents the signatures of the signer.
#[derive(Debug)]
pub struct Signatures {
    /// The size of the signature.
    pub size: usize,
    /// The signature algorithm ID of the signature.
    pub signature_algorithm_id: u32,
    /// The signature of the signer.
    pub signature: Vec<u8>,
}

/// The `TinyRawData` struct represents the tiny raw data of the signed data.
#[derive(Debug)]
pub struct TinyRawData {
    /// The size of the tiny raw data.
    pub size: usize,
    /// The ID of the tiny raw data.
    pub id: u32,
    /// The data of the tiny raw data.
    pub data: Vec<u8>,
}
