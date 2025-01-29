//! # Common types for scheme

use serde::Serialize;

use crate::{
    add_space, to_hexe,
    utils::{print_hexe, MagicNumberDecoder, MyReader},
};

/// The `Digest` struct represents the digest of the signed data.
#[derive(Debug, Serialize)]
pub struct Digest {
    /// The size of the digest.
    pub size: usize,

    /// The signature algorithm ID of the digest.
    pub signature_algorithm_id: u32,

    /// The digest of the signed data.
    pub digest: Vec<u8>,
}

/// The `Digests` struct represents the digests of the signed data.
#[derive(Debug, Serialize)]
pub struct Digests {
    /// The size of the digests.
    pub size: usize,

    /// The digests of the signed data.
    pub digests_data: Vec<Digest>,
}

impl Digests {
    /// Parses the digest of the signed data.
    pub fn parse(data: &mut MyReader) -> Self {
        let size_digests = data.read_size();
        let mut digests = Self {
            size: size_digests,
            digests_data: Vec::new(),
        };
        add_space!(12);
        println!("size_digests: {}", size_digests);
        let max_pos_digests = data.get_pos() + size_digests;
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
            digests.digests_data.push(Digest {
                size: size_one_digest,
                signature_algorithm_id,
                digest,
            })
        }
        digests
    }
}

/// The `Certificates` struct represents the certificates of the signed data.
#[derive(Debug, Serialize)]
pub struct Certificates {
    /// The size of the certificates.
    pub size: usize,

    /// The certificates of the signed data.
    pub certificates_data: Vec<Certificate>,
}

impl Certificates {
    /// Parses the certificates of the signed data.
    pub fn parse(data: &mut MyReader) -> Self {
        let size_certificates = data.read_size();
        let mut certificates = Certificates {
            size: size_certificates,
            certificates_data: Vec::new(),
        };
        add_space!(12);
        println!("size_certificates: {}", size_certificates);
        let pos_max_cert = data.get_pos() + size_certificates;
        while data.get_pos() < pos_max_cert {
            let certificate_size = data.read_size();
            add_space!(16);
            println!("certificate_size: {}", certificate_size);
            let certificate = data.get_to(certificate_size).to_vec();
            add_space!(16);
            print_hexe("certificate", &certificate);
            certificates
                .certificates_data
                .push(Certificate { certificate });
        }
        certificates
    }
}

/// The `Certificate` struct represents the certificate of the signed data.
#[derive(Debug, Serialize)]
pub struct Certificate {
    /// The certificate of the signed data.
    pub certificate: Vec<u8>,
}

/// The `Signatures` struct represents the signatures of the signer.
#[derive(Debug, Serialize)]
pub struct Signatures {
    /// The size of the signatures.
    pub size: usize,

    /// The signatures of the signer.
    pub signatures_data: Vec<Signature>,
}

impl Signatures {
    /// Parses the signatures of the signer.
    pub fn parse(data: &mut MyReader) -> Self {
        let size = data.read_size();
        add_space!(8);
        println!("signatures_size: {}", size);
        let mut signatures = Self {
            size,
            signatures_data: Vec::new(),
        };
        if size == 0 {
            return signatures;
        }
        let mut data = data.as_slice(size);
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
            signatures.signatures_data.push(Signature {
                size: size_one_signature,
                signature_algorithm_id,
                signature,
            });
        }
        signatures
    }
}

/// The `Signature` struct represents the signature of the signer.
#[derive(Debug, Serialize)]
pub struct Signature {
    /// The size of the signature.
    pub size: usize,
    /// The signature algorithm ID of the signature.
    pub signature_algorithm_id: u32,
    /// The signature of the signer.
    pub signature: Vec<u8>,
}

/// The `AdditionalAttributes` struct represents the additional attributes of the signed data.
#[derive(Debug, Serialize)]
pub struct AdditionalAttributes {
    /// The size of the additional attributes.
    pub size: usize,
    /// The additional attributes of the signed data.
    pub additional_attributes_data: Vec<TinyRawData>,
}

impl AdditionalAttributes {
    /// Parses the additional attributes of the signed data.
    pub fn parse(data: &mut MyReader) -> Self {
        let size_additional_attributes = data.read_size();
        let mut additional_attributes = Self {
            size: size_additional_attributes,
            additional_attributes_data: Vec::new(),
        };
        add_space!(12);
        println!("size_additional_attributes: {}", size_additional_attributes);
        let max_pos_attributes = data.get_pos() + size_additional_attributes;
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
            additional_attributes
                .additional_attributes_data
                .push(TinyRawData {
                    size: additional_attributes_size,
                    id,
                    data: attribute_value,
                });
        }
        additional_attributes
    }
}

/// The `TinyRawData` struct represents the tiny raw data of the signed data.
#[derive(Debug, Serialize)]
pub struct TinyRawData {
    /// The size of the tiny raw data.
    pub size: usize,
    /// The ID of the tiny raw data.
    pub id: u32,
    /// The data of the tiny raw data.
    pub data: Vec<u8>,
}

/// The `PublicKey` struct represents the public key of the signer.
#[derive(Debug, Serialize)]
pub struct PubKey {
    /// The size of the public key.
    pub size: usize,
    /// The data of the public key.
    pub data: Vec<u8>,
}

impl PubKey {
    /// Parses the public key of the signer.
    pub fn parse(data: &mut MyReader) -> Self {
        let size = data.read_size();
        add_space!(8);
        println!("pub_key_length: {}", size);
        let data = &mut data.as_slice(size);
        add_space!(12);
        println!("pub_key: {:}...", to_hexe(data.get_to(20)));
        Self {
            size,
            data: data.to_vec(),
        }
    }
}
