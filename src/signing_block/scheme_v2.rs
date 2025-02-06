//! From
//! <https://source.android.com/docs/security/features/apksigning/v2>

use std::mem;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::add_space;
use crate::common::AdditionalAttributes;
use crate::common::Certificates;
use crate::common::Digests;
use crate::common::PubKey;
use crate::common::Signatures;
use crate::utils::print_string;
use crate::MyReader;

/// Signature Scheme V2
pub const SIGNATURE_SCHEME_V2_BLOCK_ID: u32 = 0x7109871a;

/// The `SignatureSchemeV2` struct represents the V2 signature scheme.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SignatureSchemeV2 {
    /// The size of the signature scheme.
    /// u64
    pub size: usize,

    /// The ID of the signature scheme.
    pub id: u32,

    /// The signers of the signature scheme.
    pub signers: Signers,
}

/// The `Signers` struct represents the signers of the signature scheme.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Signers {
    /// The size of the signers
    pub size: usize,

    /// The signers of the signature scheme.
    pub signers_data: Vec<Signer>,
}

impl Signers {
    /// Create a new signers
    pub fn new(signers_data: Vec<Signer>) -> Self {
        let size = signers_data
            .iter()
            .fold(0, |acc, s| acc + s.size + mem::size_of::<u32>());
        Self { size, signers_data }
    }

    /// Parse the signers
    /// # Errors
    /// Returns a string if the parsing fails.
    pub fn parse(data: &mut MyReader) -> Result<Self, String> {
        let size_signers = data.read_size()?;
        let mut signers = Self {
            size: size_signers,
            signers_data: Vec::new(),
        };
        add_space!(4);
        print_string!("size_signers: {}", size_signers);
        let data = &mut data.as_slice(size_signers)?;
        while data.get_pos() < data.len() {
            let signer = Signer::parse(data)?;
            signers.signers_data.push(signer);
        }
        Ok(signers)
    }
    /// Serialize to u8
    pub fn to_u8(&self) -> Vec<u8> {
        let content = self
            .signers_data
            .iter()
            .flat_map(|s| s.to_u8())
            .collect::<Vec<u8>>();
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

/// The `Signer` struct represents the signer of the signature scheme.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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

impl Signer {
    /// Create a new signer
    pub fn new(signed_data: SignedData, signatures: Signatures, pub_key: PubKey) -> Self {
        let size = mem::size_of::<u32>()
            + signed_data.size
            + mem::size_of::<u32>()
            + signatures.size
            + mem::size_of::<u32>()
            + pub_key.size;
        Self {
            size,
            signed_data,
            signatures,
            pub_key,
        }
    }
    /// Parse the signer
    /// # Errors
    /// Returns a string if the parsing fails.
    pub fn parse(data: &mut MyReader) -> Result<Self, String> {
        let size_one_signer = data.read_size()?;
        add_space!(8);
        print_string!("size_one_signer: {}", size_one_signer);
        let signed_data = SignedData::parse(data)?;
        let signatures = Signatures::parse(data)?;
        let pub_key = PubKey::parse(data)?;
        Ok(Self {
            size: size_one_signer,
            signed_data,
            signatures,
            pub_key,
        })
    }
    /// Serialize to u8
    pub fn to_u8(&self) -> Vec<u8> {
        let content = [
            self.signed_data.to_u8(),
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
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SignedData {
    /// The size of the signed data.
    pub size: usize,

    /// The digests of the signed data.
    pub digests: Digests,

    /// The certificates of the signed data.
    pub certificates: Certificates,

    /// The additional attributes of the signed data.
    pub additional_attributes: AdditionalAttributes,

    /// auto fix the 4 bytes padding at the end of signed data - Always initialized to true
    ///
    ///  If true auto add 4 to the [`SignedData::size`] attribute when using new
    ///
    /// This size will create a tiny 4 bytes padding when using [`SignedData::to_u8`] method
    ///
    /// This attribute is still in public to allow the user to create a custom SignedData
    /// but it is not recommended to change it manually - use at your own risk
    ///
    /// Bug from apksigner tool - Thanks @obfusk
    pub _private_auto_padding_fix: bool,
}

impl SignedData {
    /// Create a new signed data
    pub fn new(
        digests: Digests,
        certificates: Certificates,
        additional_attributes: AdditionalAttributes,
    ) -> Self {
        let auto_padding_fix = true;
        let size = mem::size_of::<u32>()
            + digests.size
            + mem::size_of::<u32>()
            + certificates.size
            + mem::size_of::<u32>()
            + additional_attributes.size;
        let size = if auto_padding_fix { size + 4 } else { size };
        Self {
            size,
            digests,
            certificates,
            additional_attributes,
            _private_auto_padding_fix: auto_padding_fix,
        }
    }

    /// Parse the signed data
    /// # Errors
    /// Returns a string if the parsing fails.
    pub fn parse(data: &mut MyReader) -> Result<Self, String> {
        let size_signed_data = data.read_size()?;
        add_space!(8);
        print_string!("size_signed_data: {}", size_signed_data);
        let data = &mut data.as_slice(size_signed_data)?;
        let digests = Digests::parse(data)?;
        let certificates = Certificates::parse(data)?;
        let additional_attributes = AdditionalAttributes::parse(data)?;
        Ok(Self {
            size: size_signed_data,
            digests,
            certificates,
            additional_attributes,
            _private_auto_padding_fix: true,
        })
    }

    /// Serialize to u8
    pub fn to_u8(&self) -> Vec<u8> {
        let content = [
            self.digests.to_u8(),
            self.certificates.to_u8(),
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

impl SignatureSchemeV2 {
    /// Create a new signature scheme V2
    pub fn new(signers: Signers) -> Self {
        let size = mem::size_of::<u32>() + mem::size_of::<u32>() + signers.size;
        Self {
            size,
            id: SIGNATURE_SCHEME_V2_BLOCK_ID,
            signers,
        }
    }

    /// Creates a new `SignatureSchemeV2` with the given size, ID, and data.
    /// # Errors
    /// Returns a string if the parsing fails.
    pub fn parse(size: usize, id: u32, data: &mut MyReader) -> Result<Self, String> {
        Ok(Self {
            size,
            id,
            signers: Signers::parse(data)?,
        })
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
