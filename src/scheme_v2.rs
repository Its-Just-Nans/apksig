//! From
//! https://source.android.com/docs/security/features/apksigning/v2

use crate::add_space;
use crate::common::Certificate;
use crate::common::Digest;
use crate::common::Signatures;
use crate::common::TinyRawData;
use crate::to_hexe;
use crate::utils::print_hexe;
use crate::MagicNumberDecoder;
use crate::MyReader;

/// Signature Scheme V2
pub const SIGNATURE_SCHEME_V2_BLOCK_ID: u32 = 0x7109871a;

/// The `SignatureSchemeV2` struct represents the V2 signature scheme.
#[derive(Debug)]
pub struct SignatureSchemeV2 {
    /// The size of the signature scheme.
    pub size: usize,

    /// The ID of the signature scheme.
    pub id: u32,

    /// The signers of the signature scheme.
    pub signers: Vec<Signer>,
}

/// The `Signer` struct represents the signer of the signature scheme.
#[derive(Debug)]
pub struct Signer {
    /// The size of the signer.
    pub size: u32,

    /// The signed data of the signer.
    pub signed_data: SignedData,

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

    /// The additional attributes of the signed data.
    pub additional_attributes: Vec<TinyRawData>,
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
            println!("id: {}", id);
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
            signers.push(Signer {
                size: size_one_signer as u32,
                signed_data,
                signatures,
                pub_key,
            });
        }
        signers
    }
}
