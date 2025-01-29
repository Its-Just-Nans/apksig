//! From
//! https://source.android.com/docs/security/features/apksigning/v2

use serde::Serialize;

use crate::add_space;
use crate::common::AdditionalAttributes;
use crate::common::Certificates;
use crate::common::Digests;
use crate::common::PubKey;
use crate::common::Signatures;
use crate::MyReader;

/// Signature Scheme V2
pub const SIGNATURE_SCHEME_V2_BLOCK_ID: u32 = 0x7109871a;

/// The `SignatureSchemeV2` struct represents the V2 signature scheme.
#[derive(Debug, Serialize)]
pub struct SignatureSchemeV2 {
    /// The size of the signature scheme.
    pub size: usize,

    /// The ID of the signature scheme.
    pub id: u32,

    /// The signers of the signature scheme.
    pub signers: Vec<Signer>,
}

/// The `Signer` struct represents the signer of the signature scheme.
#[derive(Debug, Serialize)]
pub struct Signer {
    /// The size of the signer.
    pub size: usize,

    /// The signed data of the signer.
    pub signed_data: SignedData,

    /// The signatures of the signer.
    pub signatures: Signatures,

    /// The public key of the signer.
    pub pub_key: PubKey,
}

/// The `SignedData` struct represents the signed data of the signer.
#[derive(Debug, Serialize)]
pub struct SignedData {
    /// The size of the signed data.
    pub size: usize,

    /// The digests of the signed data.
    pub digests: Digests,

    /// The certificates of the signed data.
    pub certificates: Certificates,

    /// The additional attributes of the signed data.
    pub additional_attributes: AdditionalAttributes,
}

impl SignatureSchemeV2 {
    /// Creates a new `SignatureSchemeV2` with the given size, ID, and data.
    pub fn new(size: usize, id: u32, data: &mut MyReader) -> Self {
        Self {
            size,
            id,
            signers: Self::parse_data(data),
        }
    }

    /// Parses the data of the signature scheme.
    fn parse_signed_data(data: &mut MyReader) -> SignedData {
        let size = data.read_size();
        add_space!(8);
        println!("size_signed_data: {}", size);
        let data = &mut data.as_slice(size);
        let digests = Digests::parse(data);
        let certificates = Certificates::parse(data);
        let additional_attributes = AdditionalAttributes::parse(data);
        SignedData {
            size,
            digests,
            certificates,
            additional_attributes,
        }
    }

    /// Parses the signers of the signature scheme.
    fn parse_data(data: &mut MyReader) -> Vec<Signer> {
        let size_signers = data.read_size();
        add_space!(4);
        println!("size_signers: {}", size_signers);
        let mut signers = Vec::new();
        while data.get_pos() < data.len() {
            let size_one_signer = data.read_size();
            add_space!(8);
            println!("size_one_signer: {}", size_one_signer);
            let signed_data = Self::parse_signed_data(data);
            let signatures = Signatures::parse(data);
            let pub_key = PubKey::parse(data);
            signers.push(Signer {
                size: size_one_signer,
                signed_data,
                signatures,
                pub_key,
            });
        }
        signers
    }
}
