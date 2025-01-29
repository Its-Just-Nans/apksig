//! From
//! https://source.android.com/docs/security/features/apksigning/v3

use serde::Serialize;

use crate::{
    common::{AdditionalAttributes, Certificates, Digests, PubKey, Signatures},
    utils::{add_space, print_hexe, MagicNumberDecoder},
    MyReader,
};

/// Signature Scheme V3
pub const SIGNATURE_SCHEME_V3_BLOCK_ID: u32 = 0xf05368c0;

/// Proof of rotation ID
pub const PROOF_OF_ROTATION_BLOCK_ID: u32 = 0x3ba06f8c;

/// SignatureSchemeV3
#[derive(Debug, Serialize)]
pub struct SignatureSchemeV3 {
    /// size
    pub size: usize,

    /// id
    pub id: u32,

    /// data
    pub signers: Vec<Signer>,
}

/// The `Signer` struct represents the signer of the signature scheme.
#[derive(Debug, Serialize)]
pub struct Signer {
    /// The size of the signer.
    pub size: usize,

    /// The signed data of the signer.
    pub signed_data: SignedData,

    /// duplicate of minSDK value in signed data section - used to skip verification of this signature if the current platform is not in range. Must match signed data value.
    pub min_sdk: u32,

    /// duplicate of the maxSDK value in the signed data section - used to skip verification of this signature if the current platform is not in range. Must match signed data value.
    pub max_sdk: u32,

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

    /// The min SDK of the signed data.
    pub min_sdk: u32,

    /// The maximum SDK of the signed data.
    pub max_sdk: u32,

    /// The additional attributes of the signed data.
    pub additional_attributes: AdditionalAttributes,
}

/// The `ProofOfRotation` struct represents the proof of rotation.
#[derive(Debug, Serialize)]
pub struct ProofOfRotation {
    /// The levels of the proof of rotation.
    pub levels: Vec<Level>,
}

/// The `Level` struct represents the level of the proof of rotation.
#[derive(Debug, Serialize)]
pub struct Level {
    /// The signed data levels of the proof of rotation.
    pub level: SignedDataLevels,

    /// The flags of the proof of rotation.
    pub flags: u32,

    /// The signature algorithm ID of the proof of rotation.
    pub signature_algorithm_id: u32,

    /// The signature of the proof of rotation.
    pub signature: Vec<u8>,
}

/// The `SignedDataLevels` struct represents the signed data levels of the proof of rotation.
#[derive(Debug, Serialize)]
pub struct SignedDataLevels {
    /// The certificate of the signed data levels.
    pub certificate: Vec<u8>,

    /// The signature algorithm ID of the signed data levels.
    pub signature_algorithm_id: u32,
}

impl SignatureSchemeV3 {
    /// Create a new signature scheme V3
    pub fn new(size: usize, id: u32, data: &mut MyReader) -> Self {
        Self {
            size,
            id,
            signers: Self::parse_data(data),
        }
    }

    /// Parses the proof of rotation.
    pub fn parse_proof_of_rotation(data: &mut MyReader) -> ProofOfRotation {
        let levels_size = data.read_size();
        add_space!(4);
        println!("levels_size: {}", levels_size);
        let mut levels = Vec::new();
        let max_pos_levels = data.get_pos() + levels_size;
        while data.get_pos() < max_pos_levels {
            let level_size = data.read_size();
            add_space!(8);
            println!("level_size: {}", level_size);
            let certificate_size = data.read_size();
            add_space!(8);
            println!("certificate_size: {}", certificate_size);
            let certificate = data.get_to(certificate_size).to_vec();
            add_space!(8);
            print_hexe("certificate", &certificate);
            let signature_algorithm_id = data.read_u32();
            add_space!(8);
            println!(
                "signature_algorithm_id: {} {}",
                signature_algorithm_id,
                MagicNumberDecoder(signature_algorithm_id)
            );
            let flags = data.read_u32();
            add_space!(8);
            println!("flags: {}", flags);
            let signature_size = data.read_size();
            add_space!(8);
            println!("signature_size: {}", signature_size);
            let signature = data.get_to(signature_size).to_vec();
            add_space!(8);
            print_hexe("signature", &signature);
            levels.push(Level {
                level: SignedDataLevels {
                    certificate,
                    signature_algorithm_id,
                },
                flags,
                signature_algorithm_id,
                signature,
            });
        }
        ProofOfRotation { levels }
    }

    /// Returns the proof of rotation.
    pub fn proof_of_rotation(&self) -> Option<ProofOfRotation> {
        if let Some(Signer {
            signed_data:
                SignedData {
                    additional_attributes: attributes,
                    ..
                },
            ..
        }) = self.signers.first()
        {
            for attribute in attributes.additional_attributes_data.iter() {
                if attribute.id == PROOF_OF_ROTATION_BLOCK_ID {
                    return Some(Self::parse_proof_of_rotation(&mut MyReader::new(
                        &attribute.data,
                    )));
                }
            }
        }
        None
    }

    /// Parses the data of the signature scheme.
    fn parse_signed_data(data: &mut MyReader) -> SignedData {
        let size_signed_data = data.read_size();
        add_space!(8);
        println!("size_signed_data: {}", size_signed_data);
        let data = &mut data.as_slice(size_signed_data);
        let digests = Digests::parse(data);
        let certificates = Certificates::parse(data);
        let min_sdk = data.read_u32();
        add_space!(12);
        println!("min_sdk: {}", min_sdk);
        let max_sdk = data.read_u32();
        add_space!(12);
        println!("max_sdk: {}", max_sdk);
        let additional_attributes = AdditionalAttributes::parse(data);
        SignedData {
            size: size_signed_data,
            digests,
            certificates,
            min_sdk,
            max_sdk,
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
            let size = data.read_size();
            add_space!(8);
            println!("size_one_signer: {}", size);
            let signed_data = Self::parse_signed_data(data);

            let min_sdk = data.read_u32();
            add_space!(8);
            println!("min_sdk: {}", min_sdk);
            let max_sdk = data.read_u32();
            add_space!(8);
            println!("max_sdk: {}", max_sdk);
            let signatures = Signatures::parse(data);
            let pub_key = PubKey::parse(data);
            debug_assert_eq!(min_sdk, signed_data.min_sdk);
            debug_assert_eq!(max_sdk, signed_data.max_sdk);
            signers.push(Signer {
                size,
                signed_data,
                min_sdk,
                max_sdk,
                signatures,
                pub_key,
            });
        }
        signers
    }
}
