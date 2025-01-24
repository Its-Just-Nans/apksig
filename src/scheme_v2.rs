//! From
//! https://source.android.com/docs/security/features/apksigning/v2

use crate::add_space;
use crate::to_hexe;
use crate::MagicNumberDecoder;
use crate::MyReader;

#[derive(Debug)]
pub struct SignatureSchemeV2 {
    pub size: usize,
    pub id: u32,
    pub signers: Vec<Signer>,
}

#[derive(Debug)]
pub struct Signer {
    pub size: u32,
    pub signed_data: SignedData,
    pub signatures: Vec<Signatures>,
    pub pub_key: Vec<u8>,
}

#[derive(Debug)]
pub struct SignedData {
    pub digests: Vec<Digest>,
    pub certificates: Vec<Certificate>,
    pub additional_attributes: Vec<TinyRawData>,
}

#[derive(Debug)]
pub struct Digest {
    pub signature_algorithm_id: u32,
    pub digest: Vec<u8>,
}

#[derive(Debug)]
pub struct Certificate {
    pub certificate: Vec<u8>,
}

#[derive(Debug)]
pub struct Signatures {
    pub size: usize,
    pub signature_algorithm_id: u32,
    pub signature: Vec<u8>,
}

#[derive(Debug)]
pub struct TinyRawData {
    pub size: usize,
    pub id: u32,
    pub data: Vec<u8>,
}

impl SignatureSchemeV2 {
    pub fn new(size: usize, id: u32, data: &mut MyReader) -> Self {
        Self {
            size,
            id,
            signers: Self::parse_data(data),
        }
    }

    fn parse_signed_data(data: &mut MyReader) -> SignedData {
        let mut digests = Vec::new();
        let mut certificates = Vec::new();
        let mut additional_attributes = Vec::new();
        let length_digests = data.read_size();
        add_space!(12);
        println!("length_digests : {}", length_digests);
        let max_pos_digests = data.get_pos() + length_digests;
        while data.get_pos() < max_pos_digests {
            let size_one_digest = data.read_size();
            add_space!(16);
            println!("size_one_digest : {}", size_one_digest);
            let signature_algorithm_id = data.read_u32();
            add_space!(20);
            println!(
                "signature_algorithm_id : {} {}",
                signature_algorithm_id,
                MagicNumberDecoder(signature_algorithm_id)
            );
            let digest_size = data.read_size();
            add_space!(20);
            println!("digest_size : {}", digest_size);
            let mut value = vec![0; digest_size];
            value.copy_from_slice(data.get_to(digest_size));
            add_space!(20);
            println!("digest : {:?}", to_hexe(&value));
            digests.push(Digest {
                signature_algorithm_id,
                digest: value,
            })
        }
        let length_certificates = data.read_size();
        add_space!(12);
        println!("length_certificates : {}", length_certificates);
        let pos_max_cert = data.get_pos() + length_certificates;
        while data.get_pos() < pos_max_cert {
            let certificate_size = data.read_size();
            add_space!(16);
            println!("certificate_size : {}", certificate_size);
            let mut value = vec![0; certificate_size];
            value.copy_from_slice(data.get_to(certificate_size));
            add_space!(16);
            println!("certificate : {:?}...", &value[..20]);
            certificates.push(Certificate { certificate: value });
        }
        let length_additional_attributes = data.read_size();
        add_space!(12);
        println!(
            "length_additional_attributes : {}",
            length_additional_attributes
        );
        let max_pos_attributes = data.get_pos() + length_additional_attributes;
        while data.get_pos() < max_pos_attributes {
            let additional_attributes_size = data.read_size();
            add_space!(16);
            println!(
                "additional_attributes_size : {}",
                additional_attributes_size
            );
            let id = data.read_u32();
            add_space!(16);
            println!("id : {}", id);
            let size_attribute = additional_attributes_size - 4;
            let mut value = vec![0; size_attribute];
            value.copy_from_slice(data.get_to(size_attribute));
            add_space!(16);
            println!("value : {:?}...", &value[..20]);
            additional_attributes.push(TinyRawData {
                size: additional_attributes_size,
                id,
                data: value,
            });
        }
        SignedData {
            digests,
            certificates,
            additional_attributes,
        }
    }

    fn parse_signatures(data: &mut MyReader) -> Vec<Signatures> {
        let mut signatures = Vec::new();
        while data.get_pos() < data.len() {
            let size_one_signature = data.read_size();
            add_space!(12);
            println!("size_one_signature : {}", size_one_signature);
            let signature_algorithm_id = data.read_u32();
            add_space!(16);
            println!(
                "signature_algorithm_id : {} {}",
                signature_algorithm_id,
                MagicNumberDecoder(signature_algorithm_id)
            );
            let signature_size = data.read_size();
            add_space!(16);
            println!("signature_size : {}", signature_size);
            let mut signature = vec![0; signature_size];
            signature.copy_from_slice(data.get_to(signature_size));
            add_space!(16);
            println!("signature : {}...", &to_hexe(&signature[..20]));
            signatures.push(Signatures {
                size: size_one_signature,
                signature_algorithm_id,
                signature,
            });
        }
        signatures
    }

    fn parse_pub_key(data: &mut MyReader) -> Vec<u8> {
        add_space!(12);
        println!("pub_key : {:}...", to_hexe(data.get_to(20)));
        data.to_vec()
    }

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
