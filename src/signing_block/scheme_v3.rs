//! From
//! https://source.android.com/docs/security/features/apksigning/v3

use std::mem;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "directprint")]
use crate::utils::MagicNumberDecoder;

use crate::utils::{add_space, print_hexe, print_string};

use crate::{
    common::{AdditionalAttributes, Certificates, Digests, PubKey, Signatures},
    MyReader,
};

/// Signature Scheme V3
pub const SIGNATURE_SCHEME_V3_BLOCK_ID: u32 = 0xf05368c0;

/// Proof of rotation ID
pub const PROOF_OF_ROTATION_BLOCK_ID: u32 = 0x3ba06f8c;

/// SignatureSchemeV3
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SignatureSchemeV3 {
    /// size
    /// u64
    pub size: usize,

    /// id
    pub id: u32,

    /// data
    pub signers: Signers,
}

/// Signers
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Signers {
    /// size
    pub size: usize,

    /// signers
    pub signers_data: Vec<Signer>,
}

impl Signers {
    /// Parse the signers
    /// # Errors
    /// Returns a string if the data is not valid
    pub fn parse(data: &mut MyReader) -> Result<Self, String> {
        let size_signers = data.read_size()?;
        let mut signers = Self {
            size: size_signers,
            signers_data: Vec::new(),
        };
        add_space!(4);
        #[cfg(feature = "directprint")]
        print_string!("size_signers: {}", size_signers);
        while data.get_pos() < data.len() {
            signers.signers_data.push(Signer::parse(data)?);
        }
        Ok(signers)
    }

    /// Serialize to u8
    pub fn to_u8(&self) -> Vec<u8> {
        let content = self
            .signers_data
            .iter()
            .map(|signer| signer.to_u8())
            .collect::<Vec<Vec<u8>>>()
            .concat();
        [(self.size as u32).to_le_bytes()[..].to_vec(), content].concat()
    }
}

/// The `Signer` struct represents the signer of the signature scheme.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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

impl Signer {
    /// Parse the signer
    /// # Errors
    /// Returns a string if the data is not valid
    pub fn parse(data: &mut MyReader) -> Result<Self, String> {
        let size = data.read_size()?;
        add_space!(8);
        print_string!("size: {}", size);
        let signed_data = SignedData::parse(data)?;
        let min_sdk = data.read_u32()?;
        add_space!(8);
        print_string!("min_sdk: {}", min_sdk);
        let max_sdk = data.read_u32()?;
        add_space!(8);
        print_string!("max_sdk: {}", max_sdk);
        let signatures = Signatures::parse(data)?;
        let pub_key = PubKey::parse(data)?;
        Ok(Self {
            size,
            signed_data,
            min_sdk,
            max_sdk,
            signatures,
            pub_key,
        })
    }

    /// Serialize to u8
    pub fn to_u8(&self) -> Vec<u8> {
        let content = [
            self.signed_data.to_u8(),
            self.min_sdk.to_le_bytes()[..].to_vec(),
            self.max_sdk.to_le_bytes()[..].to_vec(),
            self.signatures.to_u8(),
            self.pub_key.to_u8(),
        ]
        .concat();
        let padding = match self.size.checked_sub(content.len()) {
            Some(calculated_size) => vec![0; calculated_size],
            None => vec![],
        };
        [
            (self.size as u32).to_le_bytes()[..].to_vec(),
            content,
            padding,
        ]
        .concat()
    }
}

/// The `SignedData` struct represents the signed data of the signer.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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

impl SignedData {
    /// Parse the signed data
    /// # Errors
    /// Returns a string if the data is not valid
    pub fn parse(data: &mut MyReader) -> Result<Self, String> {
        let size_signed_data = data.read_size()?;
        add_space!(8);
        print_string!("size_signed_data: {}", size_signed_data);
        let digests = Digests::parse(data)?;
        let certificates = Certificates::parse(data)?;
        let min_sdk = data.read_u32()?;
        add_space!(12);
        print_string!("min_sdk: {}", min_sdk);
        let max_sdk = data.read_u32()?;
        add_space!(12);
        print_string!("max_sdk: {}", max_sdk);
        let additional_attributes = AdditionalAttributes::parse(data)?;
        Ok(Self {
            size: size_signed_data,
            digests,
            certificates,
            min_sdk,
            max_sdk,
            additional_attributes,
        })
    }
    /// Serialize to u8
    pub fn to_u8(&self) -> Vec<u8> {
        let content = [
            self.digests.to_u8(),
            self.certificates.to_u8(),
            self.min_sdk.to_le_bytes()[..].to_vec(),
            self.max_sdk.to_le_bytes()[..].to_vec(),
            self.additional_attributes.to_u8(),
        ]
        .concat();
        let padding = match self.size.checked_sub(content.len()) {
            Some(calculated_size) => vec![0; calculated_size],
            None => vec![],
        };
        [
            (self.size as u32).to_le_bytes()[..].to_vec(),
            content,
            padding,
        ]
        .concat()
    }
}

/// The `ProofOfRotation` struct represents the proof of rotation.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ProofOfRotation {
    /// The levels of the proof of rotation.
    pub levels: Vec<Level>,
}

/// The `Level` struct represents the level of the proof of rotation.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Level {
    /// The size of the proof of rotation.
    pub size: usize,

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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SignedDataLevels {
    /// The certificate of the signed data levels.
    pub certificate: Vec<u8>,

    /// The signature algorithm ID of the signed data levels.
    pub signature_algorithm_id: u32,
}

impl SignatureSchemeV3 {
    /// Create a new signature scheme V3
    pub fn new(signers: Signers) -> Self {
        let size = mem::size_of::<u32>() + signers.size;
        Self {
            size,
            id: SIGNATURE_SCHEME_V3_BLOCK_ID,
            signers,
        }
    }

    /// Create a new signature scheme V3
    /// # Errors
    /// Returns a string if the data is not valid
    pub fn parse(size: usize, id: u32, data: &mut MyReader) -> Result<Self, String> {
        Ok(Self {
            size,
            id,
            signers: Signers::parse(data)?,
        })
    }

    /// Parses the proof of rotation.
    /// # Errors
    /// Returns a string if the data is not valid
    pub fn parse_proof_of_rotation(data: &mut MyReader) -> Result<ProofOfRotation, String> {
        let levels_size = data.read_size()?;
        add_space!(4);
        print_string!("levels_size: {}", levels_size);
        let mut levels = Vec::new();
        let max_pos_levels = data.get_pos() + levels_size;
        while data.get_pos() < max_pos_levels {
            let level_size = data.read_size()?;
            add_space!(8);
            print_string!("level_size: {}", level_size);
            let certificate_size = data.read_size()?;
            add_space!(8);
            print_string!("certificate_size: {}", certificate_size);
            let certificate = data.get_to(certificate_size)?.to_vec();
            add_space!(8);
            print_hexe("certificate", &certificate);
            let signature_algorithm_id = data.read_u32()?;
            add_space!(8);
            print_string!(
                "signature_algorithm_id: {} {}",
                signature_algorithm_id,
                MagicNumberDecoder(signature_algorithm_id)
            );
            let flags = data.read_u32()?;
            add_space!(8);
            print_string!("flags: {}", flags);
            let signature_size = data.read_size()?;
            add_space!(8);
            print_string!("signature_size: {}", signature_size);
            let signature = data.get_to(signature_size)?.to_vec();
            add_space!(8);
            print_hexe("signature", &signature);
            levels.push(Level {
                size: level_size,
                level: SignedDataLevels {
                    certificate,
                    signature_algorithm_id,
                },
                flags,
                signature_algorithm_id,
                signature,
            });
        }
        Ok(ProofOfRotation { levels })
    }

    /// Returns the proof of rotation.
    /// # Errors
    /// Returns a string if the data is not valid
    pub fn proof_of_rotation(&self) -> Result<Option<ProofOfRotation>, String> {
        if let Some(Signer {
            signed_data:
                SignedData {
                    additional_attributes: attributes,
                    ..
                },
            ..
        }) = self.signers.signers_data.first()
        {
            for attribute in attributes.additional_attributes_data.iter() {
                if attribute.id == PROOF_OF_ROTATION_BLOCK_ID {
                    return Ok(Some(Self::parse_proof_of_rotation(&mut MyReader::new(
                        &attribute.data,
                    ))?));
                }
            }
        }
        Ok(None)
    }

    /// Serialize to u8
    pub fn to_u8(&self) -> Vec<u8> {
        let content = [self.id.to_le_bytes()[..].to_vec(), self.signers.to_u8()].concat();
        let padding = match self.size.checked_sub(content.len()) {
            Some(calculated_size) => vec![0; calculated_size],
            None => vec![],
        };
        [
            (self.size as u64).to_le_bytes()[..].to_vec(),
            content,
            padding,
        ]
        .concat()
    }
}
