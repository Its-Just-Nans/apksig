//! # Common types for scheme

use std::mem;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "directprint")]
use crate::utils::MagicNumberDecoder;

use crate::{
    add_space,
    signing_block::algorithms::Algorithms,
    utils::{print_hexe, print_string, MyReader},
};

/// The `Digest` struct represents the digest of the signed data.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Digest {
    /// The size of the digest.
    pub size: usize,

    /// The signature algorithm ID of the digest.
    pub signature_algorithm_id: Algorithms,

    /// The digest of the signed data.
    pub digest: Vec<u8>,
}

impl Digest {
    /// Creates a new `Digest` with the given signature algorithm ID and digest.
    pub fn new(signature_algorithm_id: Algorithms, digest: Vec<u8>) -> Self {
        // size is len(signature_algorithm_id) + len(len(digest)) + len(digest)
        let size = mem::size_of::<u32>() + mem::size_of::<u32>() + digest.len();
        Self {
            size,
            signature_algorithm_id,
            digest,
        }
    }
    /// Parses the digest of the signed data.
    /// # Errors
    /// Returns a string if the data is not valid.
    pub fn parse(data: &mut MyReader) -> Result<Self, String> {
        let size = data.read_size()?;
        add_space!(16);
        #[cfg(feature = "directprint")]
        print_string!("digest_size: {}", size);
        let signature_algorithm_id = data.read_u32()?;
        let algo = Algorithms::from(signature_algorithm_id);
        add_space!(20);
        #[cfg(feature = "directprint")]
        print_string!(
            "signature_algorithm_id: {} {}",
            signature_algorithm_id,
            algo
        );
        let digest_size = data.read_size()?;
        add_space!(20);
        #[cfg(feature = "directprint")]
        print_string!("digest_size: {}", digest_size);
        let digest = data.get_to(digest_size)?.to_vec();
        add_space!(20);
        #[cfg(feature = "directprint")]
        print_hexe("digest", &digest);
        Ok(Self {
            size,
            signature_algorithm_id: algo,
            digest,
        })
    }
    /// Serialize to u8
    pub fn to_u8(&self) -> Vec<u8> {
        let content = [
            u32::from(&self.signature_algorithm_id).to_le_bytes()[..].to_vec(),
            (self.digest.len() as u32).to_le_bytes()[..].to_vec(),
            self.digest.to_vec(),
        ]
        .concat();
        let padding = self
            .size
            .checked_sub(content.len())
            .map_or_else(std::vec::Vec::new, |calculated_size| {
                vec![0; calculated_size]
            });
        [
            (self.size as u32).to_le_bytes()[..].to_vec(),
            content,
            padding,
        ]
        .concat()
    }
}

/// The `Digests` struct represents the digests of the signed data.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Digests {
    /// The size of the digests.
    pub size: usize,

    /// The digests of the signed data.
    pub digests_data: Vec<Digest>,
}

impl Digests {
    /// Creates a new `Digests` with the given digests.
    pub fn new(digests_data: Vec<Digest>) -> Self {
        let size = digests_data
            .iter()
            .fold(0, |acc, d| acc + d.size + mem::size_of::<u32>());
        Self { size, digests_data }
    }

    /// Parses the digest of the signed data.
    /// # Errors
    /// Returns a string if the data is not valid.
    pub fn parse(data: &mut MyReader) -> Result<Self, String> {
        let size_digests = data.read_size()?;
        let mut digests = Self {
            size: size_digests,
            digests_data: Vec::new(),
        };
        add_space!(12);
        #[cfg(feature = "directprint")]
        print_string!("size_digests: {}", size_digests);
        let data = &mut data.as_slice(size_digests)?;
        let max_pos_digests = data.get_pos() + size_digests;
        while data.get_pos() < max_pos_digests {
            digests.digests_data.push(Digest::parse(data)?);
        }
        Ok(digests)
    }

    /// Serialize to u8
    pub fn to_u8(&self) -> Vec<u8> {
        let content = self
            .digests_data
            .iter()
            .flat_map(|d| d.to_u8())
            .collect::<Vec<u8>>();
        let padding = self
            .size
            .checked_sub(content.len())
            .map_or_else(std::vec::Vec::new, |calculated_size| {
                vec![0; calculated_size]
            });
        [
            (self.size as u32).to_le_bytes()[..].to_vec(),
            content,
            padding,
        ]
        .concat()
    }
}

/// The `Certificates` struct represents the certificates of the signed data.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Certificates {
    /// The size of the certificates.
    pub size: usize,

    /// The certificates of the signed data.
    pub certificates_data: Vec<Certificate>,
}

impl Certificates {
    /// Creates a new `Certificates` with the given certificates.
    pub fn new(certificates_data: Vec<Certificate>) -> Self {
        let size = certificates_data
            .iter()
            .fold(0, |acc, c| acc + c.size + mem::size_of::<u32>());
        Self {
            size,
            certificates_data,
        }
    }

    /// Parses the certificates of the signed data.
    /// # Errors
    /// Returns a string if the data is not valid.
    pub fn parse(data: &mut MyReader) -> Result<Self, String> {
        let size_certificates = data.read_size()?;
        let mut certificates = Self {
            size: size_certificates,
            certificates_data: Vec::new(),
        };
        add_space!(12);
        print_string!("size_certificates: {}", size_certificates);
        let pos_max_cert = data.get_pos() + size_certificates;
        while data.get_pos() < pos_max_cert {
            certificates
                .certificates_data
                .push(Certificate::parse(data)?);
        }
        Ok(certificates)
    }

    /// Serialize to u8
    pub fn to_u8(&self) -> Vec<u8> {
        let content = self
            .certificates_data
            .iter()
            .flat_map(|c| c.to_u8())
            .collect::<Vec<u8>>();
        let padding = self
            .size
            .checked_sub(content.len())
            .map_or_else(std::vec::Vec::new, |calculated_size| {
                vec![0; calculated_size]
            });
        [
            (self.size as u32).to_le_bytes()[..].to_vec(),
            content,
            padding,
        ]
        .concat()
    }
}

/// The `Certificate` struct represents the certificate of the signed data.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Certificate {
    /// The certificate of the signed data.
    pub size: usize,
    /// The certificate of the signed data.
    pub certificate: Vec<u8>,
}

impl Certificate {
    /// Creates a new `Certificate` with the given certificate.
    pub fn new(certificate: Vec<u8>) -> Self {
        Self {
            size: certificate.len(),
            certificate,
        }
    }

    /// Returns the SHA256 hash of the certificate.
    #[cfg(feature = "hash")]
    pub fn sha256_cert(&self) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&self.certificate);
        hasher.finalize().to_vec()
    }

    /// Returns the MD5 hash of the certificate.
    #[cfg(feature = "hash")]
    pub fn md5_cert(&self) -> Vec<u8> {
        md5::compute(&self.certificate).to_vec()
    }

    /// Decodes the certificate of the signed data.
    #[cfg(feature = "hash")]
    pub fn sha1_cert(&self) -> Vec<u8> {
        use sha1::{Digest, Sha1};
        let mut hasher = Sha1::new();
        hasher.update(&self.certificate);
        hasher.finalize().to_vec()
    }

    /// Decodes the certificate of the signed data.
    /// # Errors
    /// Returns a string if the data is not valid.
    #[cfg(feature = "certificate")]
    pub fn get_issuer(&self) -> Result<(String, String), String> {
        use x509_parser::prelude::FromDer;

        let res = x509_parser::prelude::X509Certificate::from_der(&self.certificate);
        match res {
            Ok((_rem, cert)) => {
                let issuer = cert.issuer.to_string();
                let subject = cert.subject.to_string();
                Ok((issuer, subject))
            }
            _ => Err("x509 parsing failed".to_string()),
        }
    }

    /// Parses the certificate of the signed data.
    /// # Errors
    /// Returns a string if the data is not valid.
    pub fn parse(data: &mut MyReader) -> Result<Self, String> {
        let size = data.read_size()?;
        add_space!(16);
        print_string!("certificate_size: {}", size);
        let certificate = data.get_to(size)?.to_vec();
        add_space!(16);
        print_hexe("certificate", &certificate);
        Ok(Self { size, certificate })
    }

    /// Serialize to u8
    pub fn to_u8(&self) -> Vec<u8> {
        let content = self.certificate.to_vec();
        let padding = self
            .size
            .checked_sub(content.len())
            .map_or_else(std::vec::Vec::new, |calculated_size| {
                vec![0; calculated_size]
            });
        [
            (self.size as u32).to_le_bytes()[..].to_vec(),
            content,
            padding,
        ]
        .concat()
    }
}

/// The `Signatures` struct represents the signatures of the signer.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Signatures {
    /// The size of the signatures.
    pub size: usize,

    /// The signatures of the signer.
    pub signatures_data: Vec<Signature>,
}

impl Signatures {
    /// Creates a new `Signatures` with the given signatures.
    pub fn new(signatures_data: Vec<Signature>) -> Self {
        let size = signatures_data
            .iter()
            .fold(0, |acc, s| acc + s.size + mem::size_of::<u32>());
        Self {
            size,
            signatures_data,
        }
    }

    /// Parses the signatures of the signer.
    /// # Errors
    /// Returns a string if the data is not valid.
    pub fn parse(data: &mut MyReader) -> Result<Self, String> {
        let size = data.read_size()?;
        add_space!(8);
        print_string!("signatures_size: {}", size);
        let mut signatures = Self {
            size,
            signatures_data: Vec::new(),
        };
        if size == 0 {
            return Ok(signatures);
        }
        let max_signatures = data.get_pos() + size;
        while data.get_pos() < max_signatures {
            signatures.signatures_data.push(Signature::parse(data)?);
        }
        Ok(signatures)
    }

    /// Serialize to u8
    pub fn to_u8(&self) -> Vec<u8> {
        let content = self
            .signatures_data
            .iter()
            .flat_map(|s| s.to_u8())
            .collect::<Vec<u8>>();
        let padding = self
            .size
            .checked_sub(content.len())
            .map_or_else(std::vec::Vec::new, |calculated_size| {
                vec![0; calculated_size]
            });
        [
            (self.size as u32).to_le_bytes()[..].to_vec(),
            content,
            padding,
        ]
        .concat()
    }
}

/// The `Signature` struct represents the signature of the signer.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Signature {
    /// The size of the signature.
    pub size: usize,
    /// The signature algorithm ID of the signature.
    pub signature_algorithm_id: Algorithms,
    /// The signature of the signer.
    pub signature: Vec<u8>,
}

impl Signature {
    /// Creates a new `Signature` with the given signature algorithm ID and signature.
    pub fn new(signature_algorithm_id: Algorithms, signature: Vec<u8>) -> Self {
        // size is len(signature_algorithm_id) + len(len(signature)) + len(signature)
        let size = mem::size_of::<u32>() + mem::size_of::<u32>() + signature.len();
        Self {
            size,
            signature_algorithm_id,
            signature,
        }
    }

    /// Parses the signature of the signer.
    /// # Errors
    /// Returns a string if the data is not valid.
    pub fn parse(data: &mut MyReader) -> Result<Self, String> {
        let size = data.read_size()?;
        add_space!(12);
        print_string!("signature_size: {}", size);
        let signature_algorithm_id = data.read_u32()?;
        let algo = Algorithms::from(signature_algorithm_id);
        add_space!(12);
        print_string!(
            "signature_algorithm_id: {} {}",
            signature_algorithm_id,
            algo
        );
        let signature_size = data.read_size()?;
        add_space!(12);
        print_string!("signature_size: {}", signature_size);
        let signature = data.get_to(signature_size)?.to_vec();
        add_space!(12);
        print_hexe("signature", &signature);
        Ok(Self {
            size,
            signature_algorithm_id: algo,
            signature,
        })
    }

    /// Serialize to u8
    pub fn to_u8(&self) -> Vec<u8> {
        let content = [
            (u32::from(&self.signature_algorithm_id)).to_le_bytes()[..].to_vec(),
            (self.signature.len() as u32).to_le_bytes()[..].to_vec(),
            self.signature.to_vec(),
        ]
        .concat();
        let padding = self
            .size
            .checked_sub(content.len())
            .map_or_else(std::vec::Vec::new, |calculated_size| {
                vec![0; calculated_size]
            });
        [
            (self.size as u32).to_le_bytes()[..].to_vec(),
            content,
            padding,
        ]
        .concat()
    }
}

/// The `AdditionalAttributes` struct represents the additional attributes of the signed data.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AdditionalAttributes {
    /// The size of the additional attributes.
    pub size: usize,
    /// The additional attributes of the signed data.
    pub additional_attributes_data: Vec<AdditionalAttribute>,
}

impl AdditionalAttributes {
    /// Creates a new `AdditionalAttributes` with the given additional attributes.
    pub fn new(additional_attributes_data: Vec<AdditionalAttribute>) -> Self {
        let size = additional_attributes_data
            .iter()
            .fold(0, |acc, a| acc + a.size + mem::size_of::<u32>());
        Self {
            size,
            additional_attributes_data,
        }
    }

    /// Parses the additional attributes of the signed data.
    /// # Errors
    /// Returns a string if the data is not valid.
    pub fn parse(data: &mut MyReader) -> Result<Self, String> {
        let size_additional_attributes = data.read_size()?;
        let mut additional_attributes = Self {
            size: size_additional_attributes,
            additional_attributes_data: Vec::new(),
        };
        add_space!(12);
        print_string!("size_additional_attributes: {}", size_additional_attributes);
        let max_pos_attributes = data.get_pos() + size_additional_attributes;
        while data.get_pos() < max_pos_attributes {
            additional_attributes
                .additional_attributes_data
                .push(AdditionalAttribute::parse(data)?);
        }
        Ok(additional_attributes)
    }

    /// Serialize to u8
    pub fn to_u8(&self) -> Vec<u8> {
        let content = self
            .additional_attributes_data
            .iter()
            .flat_map(|a| a.to_u8())
            .collect::<Vec<u8>>();
        let padding = self
            .size
            .checked_sub(content.len())
            .map_or_else(std::vec::Vec::new, |calculated_size| {
                vec![0; calculated_size]
            });
        [
            (self.size as u32).to_le_bytes()[..].to_vec(),
            content,
            padding,
        ]
        .concat()
    }
}

/// The `TinyRawData` struct represents the tiny raw data of the signed data.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AdditionalAttribute {
    /// The size of the tiny raw data.
    pub size: usize,
    /// The ID of the tiny raw data.
    pub id: u32,
    /// The data of the tiny raw data.
    pub data: Vec<u8>,
}

impl AdditionalAttribute {
    /// Parses the tiny raw data of the signed data.
    /// # Errors
    /// Returns a string if the data is not valid.
    pub fn parse(data: &mut MyReader) -> Result<Self, String> {
        let size = data.read_size()?;
        add_space!(16);
        print_string!("tiny_raw_data_size: {}", size);
        let id = data.read_u32()?;
        add_space!(20);
        print_string!("id: {} {}", id, MagicNumberDecoder::Normal(id));
        let data_size = match size.checked_sub(4) {
            Some(size) => size,
            None => return Err("Invalid size".to_string()),
        };
        let data = data.get_to(data_size)?.to_vec();
        add_space!(20);
        print_hexe("data", &data);
        Ok(Self { size, id, data })
    }
    /// Serialize to u8
    pub fn to_u8(&self) -> Vec<u8> {
        let content = [self.id.to_le_bytes()[..].to_vec(), self.data.to_vec()].concat();
        let padding = self
            .size
            .checked_sub(content.len())
            .map_or_else(std::vec::Vec::new, |calculated_size| {
                vec![0; calculated_size]
            });
        [
            (self.size as u32).to_le_bytes()[..].to_vec(),
            content,
            padding,
        ]
        .concat()
    }
}

/// The `PublicKey` struct represents the public key of the signer.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PubKey {
    /// The size of the public key.
    pub size: usize,
    /// The data of the public key.
    pub data: Vec<u8>,
}

impl PubKey {
    /// Creates a new `PublicKey` with the given data.
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            size: data.len(),
            data,
        }
    }

    /// Parses the public key of the signer.
    /// # Errors
    /// Returns a string if the data is not valid.
    pub fn parse(data: &mut MyReader) -> Result<Self, String> {
        let size = data.read_size()?;
        add_space!(8);
        print_string!("pub_key_length: {}", size);
        add_space!(12);
        let data = data.get_to(size)?.to_vec();
        print_hexe("pub_key", &data);
        Ok(Self { size, data })
    }

    /// Serialize to u8
    pub fn to_u8(&self) -> Vec<u8> {
        let content = self.data.to_vec();
        let padding = self
            .size
            .checked_sub(content.len())
            .map_or_else(std::vec::Vec::new, |calculated_size| {
                vec![0; calculated_size]
            });
        [
            (self.size as u32).to_le_bytes()[..].to_vec(),
            content,
            padding,
        ]
        .concat()
    }
}
