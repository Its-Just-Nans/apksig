//! Handling the APK file by providing methods as `Apk` struct.

use std::{fs::File, path::PathBuf};

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
                            Err(e) => return Err(e.to_string()),
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
}
