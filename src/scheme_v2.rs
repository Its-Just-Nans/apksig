use crate::read_u32;
use crate::to_hexe;
use crate::MagicNumberDecoder;

#[derive(Debug)]
pub struct SignatureSchemeV2Block {
    size: u64,
    id: u32,
    signers: Vec<Signer>,
}

#[derive(Debug)]
struct Signer {
    size: u32,
    signed_data: SignedData,
    signatures: Vec<Signatures>,
    pub_key: Vec<u8>,
}

#[derive(Debug)]
struct SignedData {
    digests: Vec<Digest>,
    certificates: Vec<Certificate>,
    additional_attributes: Vec<TinyRawData>,
}

#[derive(Debug)]
struct Digest {
    signature_algorithm_id: u32,
    digest: Vec<u8>,
}

#[derive(Debug)]
struct Certificate {
    certificate: Vec<u8>,
}

#[derive(Debug)]
struct Signatures {
    signature_algorithm_id: u32,
    signature: Vec<u8>,
}

#[derive(Debug)]
struct TinyRawData {
    size: u32,
    id: u32,
    data: Vec<u8>,
}

impl SignatureSchemeV2Block {
    pub fn new(size: u64, id: u32, data: &[u8]) -> Self {
        SignatureSchemeV2Block {
            size,
            id,
            signers: Self::parse_data(data),
        }
    }

    fn parse_signed_data(data: &[u8]) -> SignedData {
        let mut digests = Vec::new();
        let mut certificates = Vec::new();
        let mut additional_attributes = Vec::new();
        let mut pos = 0;
        let length_digests = read_u32(&data[pos..pos + 4]) as usize;
        pos += 4;
        println!("          length_digests : {}", length_digests);
        let max_pos_digests = pos + length_digests;
        while pos < max_pos_digests {
            let size_one_digest = read_u32(&data[pos..pos + 4]);
            pos += 4;
            println!("              size_one_digest : {}", size_one_digest);
            let signature_algorithm_id = read_u32(&data[pos..pos + 4]);
            pos += 4;
            println!(
                "                  signature_algorithm_id : {} {}",
                signature_algorithm_id,
                MagicNumberDecoder(signature_algorithm_id)
            );
            let digest_size = read_u32(&data[pos..pos + 4]) as usize;
            pos += 4;
            println!("                  digest_size : {}", digest_size);
            let mut value = vec![0; digest_size as usize];
            value.copy_from_slice(&data[pos..pos + digest_size]);
            pos += digest_size as usize;
            println!("                  digest : {:?}", to_hexe(&value));
            digests.push(Digest {
                signature_algorithm_id,
                digest: value,
            })
        }
        let length_certificates = read_u32(&data[pos..pos + 4]) as usize;
        pos += 4;
        println!("          length_certificates : {}", length_certificates);
        let pos_max_cert = pos + length_certificates;
        while pos < pos_max_cert {
            let certificate_size = read_u32(&data[pos..pos + 4]) as usize;
            pos += 4;
            println!("              certificate_size : {}", certificate_size);
            let mut value = vec![0; certificate_size];
            value.copy_from_slice(&data[pos..pos + certificate_size]);
            pos += certificate_size;
            println!("              certificate : {:?}...", &value[..20]);
            certificates.push(Certificate { certificate: value });
        }
        let length_additional_attributes = read_u32(&data[pos..pos + 4]) as usize;
        pos += 4;
        println!(
            "          length_additional_attributes : {}",
            length_additional_attributes
        );
        let max_pos_attributes = pos + length_additional_attributes;
        while pos < max_pos_attributes {
            let additional_attributes_size = read_u32(&data[pos..pos + 4]) as usize;
            pos += 4;
            println!(
                "           additional_attributes : {}",
                additional_attributes_size
            );
            let id = read_u32(&data[pos..pos + 4]);
            pos += 4;
            println!("          id : {}", id);
            let size_attribute = additional_attributes_size - 4;
            let mut value = vec![0; size_attribute];
            value.copy_from_slice(&data[pos..pos + size_attribute]);
            pos += size_attribute as usize;
            additional_attributes.push(TinyRawData {
                size: additional_attributes_size as u32,
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

    fn parse_signatures(data: &[u8]) -> Vec<Signatures> {
        let mut signatures = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            let size_one_signature = read_u32(&data[pos..pos + 4]) as usize;
            pos += 4;
            println!("          size_one_signature : {}", size_one_signature);
            let signature_algorithm_id = read_u32(&data[pos..pos + 4]);
            pos += 4;
            println!(
                "              signature_algorithm_id : {} {}",
                signature_algorithm_id,
                MagicNumberDecoder(signature_algorithm_id)
            );
            let signature_size = read_u32(&data[pos..pos + 4]) as usize;
            pos += 4;
            println!("              signature_size : {}", signature_size);
            let mut signature = vec![0; signature_size as usize];
            signature.copy_from_slice(&data[pos..pos + signature_size as usize]);
            pos += signature_size as usize;
            println!(
                "              signature : {}...",
                &to_hexe(&signature[..20])
            );
            signatures.push(Signatures {
                signature_algorithm_id,
                signature,
            });
        }
        signatures
    }

    fn parse_pub_key(data: &[u8]) -> Vec<u8> {
        println!("          pub_key : {:}...", to_hexe(&data[..20]));
        data.to_vec()
    }

    fn parse_data(data: &[u8]) -> Vec<Signer> {
        let size_signers = read_u32(data);
        println!("size_signers: {}", size_signers);
        let mut signers = Vec::new();
        let mut pos = 4;
        while pos < data.len() {
            let size_one_signer = read_u32(&data[pos..pos + 4]) as usize;
            pos += 4;
            println!("  size_one_signer: {}", size_one_signer);
            let size_signed_data = read_u32(&data[pos..pos + 4]) as usize;
            pos += 4;
            println!("      size_signed_data: {}", size_signed_data);
            let signed_data = Self::parse_signed_data(&data[pos..pos + size_signed_data]);
            pos += size_signed_data;
            let signatures_length = read_u32(&data[pos..pos + 4]) as usize;
            pos += 4;
            println!("      signatures_length: {}", signatures_length);
            let signatures = if signatures_length != 0 {
                let signatures = Self::parse_signatures(&data[pos..pos + signatures_length]);
                pos += signatures_length;
                signatures
            } else {
                Vec::new()
            };
            let pub_key_length = read_u32(&data[pos..pos + 4]) as usize;
            pos += 4;
            println!("      pub_key_length: {}", pub_key_length);
            let pub_key = Self::parse_pub_key(&data[pos..pos + pub_key_length]);
            pos += pub_key_length;
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
