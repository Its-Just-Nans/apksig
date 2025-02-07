//! Handling the APK file by providing methods as `Apk` struct.

use std::{
    fs::{read, File},
    path::PathBuf,
};

use crate::{
    zip::{find_eocd, EndOfCentralDirectoryRecord},
    SigningBlock,
};

#[cfg(feature = "hash")]
use crate::{digest_apk, zip::FileOffsets, Algorithms};

#[cfg(feature = "signing")]
use crate::ValueSigningBlock;

/// The `Apk` struct represents the APK file.
#[derive(Default)]
pub struct Apk {
    /// If the APK is raw (not signed)
    pub raw: bool,

    /// The path of the APK file.
    pub path: PathBuf,

    /// The length of the APK file.
    pub file_len: usize,

    /// The signing block of the APK file.
    pub sig: Option<SigningBlock>,
}

impl Apk {
    /// Create a new APK file.
    /// # Errors
    /// Returns an error if the path is not found.
    pub fn new(path: PathBuf) -> Result<Self, std::io::Error> {
        let file = File::open(&path)?;
        let file_len = file.metadata()?.len() as usize;
        Ok(Self {
            path,
            file_len,
            ..Default::default()
        })
    }

    /// Create a new raw APK file.
    /// # Errors
    /// Returns an error if the path is not found.
    pub fn new_raw(path: PathBuf) -> Result<Self, std::io::Error> {
        Ok(Self {
            raw: true,
            ..Self::new(path)?
        })
    }

    /// Decode the signing block of the APK file.
    /// # Errors
    /// Returns a string if the decoding fails.
    pub fn get_signing_block(&self) -> Result<SigningBlock, String> {
        if self.raw {
            return Err("APK is raw".to_string());
        }
        match self.sig {
            Some(ref sig) => Ok(sig.clone()),
            None => {
                let file = File::open(&self.path).map_err(|e| e.to_string())?;
                let sig =
                    SigningBlock::from_reader(file, self.file_len, 0).map_err(|e| e.to_string())?;
                Ok(sig)
            }
        }
    }

    /// Verify the APK file.
    /// # Errors
    /// Returns a string if the verification fails.
    #[cfg(feature = "signing")]
    pub fn verify(&self) -> Result<(), String> {
        let signing_block = self.get_signing_block()?;
        for block in signing_block.content {
            match block {
                ValueSigningBlock::SignatureSchemeV2Block(v2) => {
                    let len_signer = v2.signers.signers_data.len();
                    if len_signer == 0 {
                        return Err("No signer found".to_string());
                    }
                    for idx in 0..len_signer {
                        let signer = match v2.signers.signers_data.get(idx) {
                            Some(signer) => signer,
                            None => return Err("No signer found".to_string()),
                        };
                        let signature = match signer.signatures.signatures_data.get(idx) {
                            Some(signature) => signature,
                            None => return Err("No signature found".to_string()),
                        };
                        let signature = &signature.signature;
                        let pubkey = &signer.pub_key.data;
                        let digest = match signer.signed_data.digests.digests_data.get(idx) {
                            Some(digest) => digest,
                            None => return Err("No digest found".to_string()),
                        };
                        let algo = &digest.signature_algorithm_id;

                        let signer_data = &signer.signed_data.to_u8();
                        let raw_data = match signer_data.get(4..) {
                            Some(data) => data,
                            None => return Err("Invalid signed data".to_string()),
                        };

                        match algo.verify(pubkey, raw_data, signature) {
                            Ok(_) => {}
                            Err(e) => return Err(e),
                        }
                    }
                }
                ValueSigningBlock::SignatureSchemeV3Block(_) => {
                    return Err("Signature scheme v3 is not supported for the moment".to_string());
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// find_eocd finds the End of Central Directory Record of the APK file.
    /// # Errors
    /// Returns a string if the End of Central Directory Record is not found.
    /// Or a problem occurs
    pub fn find_eocd(&self) -> Result<EndOfCentralDirectoryRecord, String> {
        let mut file = File::open(&self.path).map_err(|e| e.to_string())?;
        find_eocd(&mut file, self.file_len).map_err(|e| e.to_string())
    }

    /// Calculate the digest of the APK file.
    /// # Errors
    /// Returns a string if the digest fails.
    #[cfg(feature = "hash")]
    pub fn digest(&self, algo: &Algorithms) -> Result<Vec<u8>, String> {
        let mut file = File::open(&self.path).map_err(|e| e.to_string())?;
        let eocd = self.find_eocd()?;
        let offsets = if self.raw {
            let stop_content = eocd.cd_offset as usize;
            FileOffsets::without_signature(stop_content, eocd.file_offset, self.file_len)
        } else {
            let sig = self.get_signing_block()?;
            FileOffsets::new(
                sig.file_offset_start,
                sig.file_offset_end,
                eocd.file_offset,
                self.file_len,
            )
        };
        digest_apk(&mut file, &offsets, algo).map_err(|e| e.to_string())
    }

    /// Get the raw APK file.
    /// # Errors
    /// Returns a string if the raw APK file fails.
    pub fn get_raw_apk(&self) -> Result<Vec<u8>, String> {
        let full_raw_file = read(&self.path).map_err(|e| e.to_string())?;

        if self.raw {
            return Ok(full_raw_file);
        }

        let sig = self.get_signing_block()?;

        let start_sig = sig.file_offset_start;
        let end_sig = sig.file_offset_end;
        let size_sig = end_sig - start_sig;

        let start_without_sig = match full_raw_file.get(..start_sig) {
            Some(data) => data,
            None => return Err("Invalid start signature".to_string()),
        };
        let end_without_sig = match full_raw_file.get(end_sig..) {
            Some(data) => data,
            None => return Err("Invalid end signature".to_string()),
        };

        let eocd = self.find_eocd()?;

        let mut apk_without_signature = [start_without_sig, end_without_sig].concat();

        // verify that the signature was removed
        // so the size of the file should be the original size - size of the signature
        let file_len = self.file_len - size_sig;

        // modify the zip cd_offset
        let new_cd_offset: u32 = eocd.cd_offset - size_sig as u32;
        let idx_cd_offset = file_len - 6 - eocd.comment_len as usize;
        let idx_cd_offset_end = file_len - 2 - eocd.comment_len as usize;
        match apk_without_signature.get_mut(idx_cd_offset..idx_cd_offset_end) {
            Some(data) => data.copy_from_slice(new_cd_offset.to_le_bytes().as_ref()),
            None => return Err("Invalid cd offset".to_string()),
        }

        Ok(apk_without_signature)
    }
}
