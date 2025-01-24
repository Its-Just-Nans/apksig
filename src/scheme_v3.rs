//! From
//! https://source.android.com/docs/security/features/apksigning/v3

use crate::{
    utils::{add_space, print_hexe, to_hexe, MagicNumberDecoder},
    MyReader,
};

/// Signature Scheme V3
pub const SIGNATURE_SCHEME_V3_BLOCK_ID: u32 = 0xf05368c0;

/// Proof of rotation ID
pub const PROOF_OF_ROTATION_BLOCK_ID: u32 = 0x3ba06f8c;

/// SignatureSchemeV3
#[derive(Debug)]
pub struct SignatureSchemeV3 {
    /// size
    pub size: usize,

    /// id
    pub id: u32,

    /// data
    pub signers: Vec<Signer>,
}

/// The `Signer` struct represents the signer of the signature scheme.
#[derive(Debug)]
pub struct Signer {
    /// The size of the signer.
    pub size: u32,

    /// The signed data of the signer.
    pub signed_data: SignedData,

    /// duplicate of minSDK value in signed data section - used to skip verification of this signature if the current platform is not in range. Must match signed data value.
    pub min_sdk: u32,

    /// duplicate of the maxSDK value in the signed data section - used to skip verification of this signature if the current platform is not in range. Must match signed data value.
    pub max_sdk: u32,

    /// The signatures of the signer.
    pub signatures: Vec<Signatures>,

    /// The public key of the signer.
    pub pub_key: Vec<u8>,
}

/// The `SignedData` struct represents the signed data of the signer.
#[derive(Debug)]
pub struct SignedData {
    /// The digests of the signed data.
    pub digests: Vec<Digest>,

    /// The certificates of the signed data.
    pub certificates: Vec<Certificate>,

    /// The min SDK of the signed data.
    pub min_sdk: u32,

    /// The maximum SDK of the signed data.
    pub max_sdk: u32,

    /// The additional attributes of the signed data.
    pub additional_attributes: Vec<TinyRawData>,
}

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

/// The `ProofOfRotation` struct represents the proof of rotation.
#[derive(Debug)]
pub struct ProofOfRotation {
    /// The levels of the proof of rotation.
    pub levels: Vec<Level>,
}

/// The `Level` struct represents the level of the proof of rotation.
#[derive(Debug)]
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
#[derive(Debug)]
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
            for attribute in attributes {
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
        let mut digests = Vec::new();
        let mut certificates = Vec::new();
        let mut additional_attributes = Vec::new();
        let length_digests = data.read_size();
        add_space!(12);
        println!("length_digests: {}", length_digests);
        let max_pos_digests = data.get_pos() + length_digests;
        while data.get_pos() < max_pos_digests {
            let size_one_digest = data.read_size();
            add_space!(16);
            println!("size_one_digest: {}", size_one_digest);
            let signature_algorithm_id = data.read_u32();
            add_space!(20);
            println!(
                "signature_algorithm_id: {} {}",
                signature_algorithm_id,
                MagicNumberDecoder(signature_algorithm_id)
            );
            let digest_size = data.read_size();
            add_space!(20);
            println!("digest_size: {}", digest_size);
            let digest = data.get_to(digest_size).to_vec();
            add_space!(20);
            println!("digest: {}", to_hexe(&digest));
            digests.push(Digest {
                signature_algorithm_id,
                digest,
            })
        }
        let length_certificates = data.read_size();
        add_space!(12);
        println!("length_certificates: {}", length_certificates);
        let pos_max_cert = data.get_pos() + length_certificates;
        while data.get_pos() < pos_max_cert {
            let certificate_size = data.read_size();
            add_space!(16);
            println!("certificate_size: {}", certificate_size);
            let certificate = data.get_to(certificate_size).to_vec();
            add_space!(16);
            print_hexe("certificate", &certificate);
            certificates.push(Certificate { certificate });
        }
        let min_sdk = data.read_u32();
        add_space!(12);
        println!("min_sdk: {}", min_sdk);
        let max_sdk = data.read_u32();
        add_space!(12);
        println!("max_sdk: {}", max_sdk);

        let length_additional_attributes = data.read_size();
        add_space!(12);
        println!(
            "length_additional_attributes: {}",
            length_additional_attributes
        );
        let max_pos_attributes = data.get_pos() + length_additional_attributes;
        while data.get_pos() < max_pos_attributes {
            let additional_attributes_size = data.read_size();
            add_space!(16);
            println!("additional_attributes_size: {}", additional_attributes_size);
            let id = data.read_u32();
            add_space!(16);
            println!("id: {} {}", id, MagicNumberDecoder(id));
            let size_attribute = additional_attributes_size - 4;
            let attribute_value = data.get_to(size_attribute).to_vec();
            add_space!(16);
            print_hexe("attribute_value", &attribute_value);
            additional_attributes.push(TinyRawData {
                size: additional_attributes_size,
                id,
                data: attribute_value,
            });
        }
        SignedData {
            digests,
            certificates,
            min_sdk,
            max_sdk,
            additional_attributes,
        }
    }

    /// Parses the signatures of the signer.
    fn parse_signatures(data: &mut MyReader) -> Vec<Signatures> {
        let mut signatures = Vec::new();
        while data.get_pos() < data.len() {
            let size_one_signature = data.read_size();
            add_space!(12);
            println!("size_one_signature: {}", size_one_signature);
            let signature_algorithm_id = data.read_u32();
            add_space!(16);
            println!(
                "signature_algorithm_id: {} {}",
                signature_algorithm_id,
                MagicNumberDecoder(signature_algorithm_id)
            );
            let signature_size = data.read_size();
            add_space!(16);
            println!("signature_size: {}", signature_size);
            let signature = data.get_to(signature_size).to_vec();
            add_space!(16);
            print_hexe("signature", &signature);
            signatures.push(Signatures {
                size: size_one_signature,
                signature_algorithm_id,
                signature,
            });
        }
        signatures
    }

    /// Parses the public key of the signer.
    fn parse_pub_key(data: &mut MyReader) -> Vec<u8> {
        add_space!(12);
        println!("pub_key: {:}...", to_hexe(data.get_to(20)));
        data.to_vec()
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
            let size_signed_data = data.read_size();
            add_space!(8);
            println!("size_signed_data: {}", size_signed_data);
            let signed_data = Self::parse_signed_data(&mut data.as_slice(size_signed_data));

            let min_sdk = data.read_u32();
            add_space!(8);
            println!("min_sdk: {}", min_sdk);
            let max_sdk = data.read_u32();
            add_space!(8);
            println!("max_sdk: {}", max_sdk);

            let signatures_length = data.read_size();
            add_space!(8);
            println!("signatures_length: {}", signatures_length);
            let signatures = if signatures_length != 0 {
                Self::parse_signatures(&mut data.as_slice(signatures_length))
            } else {
                Vec::new()
            };
            let pub_key_length = data.read_size();
            add_space!(8);
            println!("pub_key_length: {}", pub_key_length);
            let pub_key = Self::parse_pub_key(&mut data.as_slice(pub_key_length));
            debug_assert_eq!(min_sdk, signed_data.min_sdk);
            debug_assert_eq!(max_sdk, signed_data.max_sdk);
            signers.push(Signer {
                size: size_one_signer as u32,
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
