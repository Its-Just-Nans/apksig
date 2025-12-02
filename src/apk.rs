//! Handling the APK file by providing methods as `Apk` struct.

use std::{
    fs::{File, read},
    io::{Read, Seek, Write, copy},
    path::PathBuf,
};

use crate::{
    SigningBlock,
    zip::{EndOfCentralDirectoryRecord, FileOffsets, find_eocd},
};

#[cfg(feature = "hash")]
use crate::{Algorithms, digest_apk};

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
    pub fn get_signing_block(&self) -> Result<SigningBlock, std::io::Error> {
        match self.sig {
            Some(ref sig) => Ok(sig.clone()),
            None => {
                if self.raw {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "APK is raw",
                    ));
                }
                let file = File::open(&self.path)?;
                let sig = SigningBlock::from_reader(file, self.file_len, 0)?;
                Ok(sig)
            }
        }
    }

    /// Verify the APK file.
    /// # Errors
    /// Returns a string if the verification fails.
    #[cfg(feature = "signing")]
    pub fn verify(&self) -> Result<(), String> {
        let signing_block = self.get_signing_block().map_err(|e| e.to_string())?;
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
                        let pubkey = &signer.pub_key.data;
                        let signer_data = &signer.signed_data.to_u8();
                        let raw_data = match signer_data.get(4..) {
                            Some(data) => data,
                            None => return Err("Invalid signed data".to_string()),
                        };
                        if signer.signatures.signatures_data.is_empty() {
                            return Err("No signature found".to_string());
                        }
                        for (idx_sig, signature) in
                            signer.signatures.signatures_data.iter().enumerate()
                        {
                            let signature = &signature.signature;
                            let digest = match signer.signed_data.digests.digests_data.get(idx_sig)
                            {
                                Some(digest) => digest,
                                None => return Err("No digest found".to_string()),
                            };
                            let algo = &digest.signature_algorithm_id;

                            match algo.verify(pubkey, raw_data, signature) {
                                Ok(_) => {}
                                Err(e) => return Err(e),
                            }
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
    pub fn find_eocd(&self) -> Result<EndOfCentralDirectoryRecord, std::io::Error> {
        let mut file = File::open(&self.path)?;
        find_eocd(&mut file, self.file_len)
    }

    /// Get the offsets of the APK file.
    /// # Errors
    /// Returns a string if the offsets are not found.
    pub fn get_offsets(&self) -> Result<FileOffsets, std::io::Error> {
        let eocd = self.find_eocd()?;
        match self.get_signing_block() {
            Ok(sig) => {
                let file_len = if self.raw {
                    self.file_len + sig.get_full_size()
                } else {
                    self.file_len
                };
                let stop_cd = if self.raw {
                    eocd.file_offset + sig.get_full_size()
                } else {
                    eocd.file_offset
                };
                Ok(FileOffsets::new(
                    sig.file_offset_start,
                    sig.file_offset_end,
                    stop_cd,
                    file_len,
                ))
            }
            Err(_) => {
                let stop_content = eocd.cd_offset as usize;
                Ok(FileOffsets::without_signature(
                    stop_content,
                    eocd.file_offset,
                    self.file_len,
                ))
            }
        }
    }

    /// Calculate the digest of the APK file.
    /// # Errors
    /// Returns a string if the digest fails.
    #[cfg(feature = "hash")]
    pub fn digest(&self, algo: &Algorithms) -> Result<Vec<u8>, std::io::Error> {
        let mut file = File::open(&self.path)?;
        let offsets = self.get_offsets()?;
        digest_apk(&mut file, &offsets, algo)
    }

    /// Get the raw APK file.
    /// # Errors
    /// Returns a string if the raw APK file fails.
    pub fn get_raw_apk(&self) -> Result<Vec<u8>, std::io::Error> {
        let full_raw_file = read(&self.path)?;

        if self.raw {
            return Ok(full_raw_file);
        }

        let sig = self.get_signing_block()?;

        let start_sig = sig.file_offset_start;
        let end_sig = sig.file_offset_end;
        let size_sig = end_sig - start_sig;

        let start_without_sig = match full_raw_file.get(..start_sig) {
            Some(data) => data,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid start signature",
                ));
            }
        };
        let mut eocd = self.find_eocd()?;
        eocd.cd_offset -= size_sig as u32;

        let eocd_serialized = eocd.to_u8();

        let end_without_sig =
            match full_raw_file.get(end_sig..(full_raw_file.len() - eocd_serialized.len())) {
                Some(data) => data,
                None => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Invalid end signature",
                    ));
                }
            };

        let apk_without_signature = [start_without_sig, end_without_sig, &eocd_serialized].concat();

        Ok(apk_without_signature)
    }

    /// Write the APK file with the signature.
    /// # Errors
    /// Returns a string if the writing fails.
    pub fn write_with_signature<W: Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        let sig = self.get_signing_block()?;
        let offsets = self.get_offsets()?;
        let mut eocd = self.find_eocd()?;
        eocd.cd_offset += sig.get_full_size() as u32;
        let oecd_serialized = eocd.to_u8();
        let eocd_len = oecd_serialized.len();

        // copy entries
        let file_reader = File::open(&self.path)?;
        let mut reader_entries = file_reader.take(offsets.stop_content as u64);
        copy(&mut reader_entries, writer)?;

        // copy signature block
        writer.write_all(&sig.to_u8())?;

        // copy zip central directory
        let mut file_reader_end = File::open(&self.path)?;
        let seek_end = (offsets.start_cd - sig.get_full_size()) as u64;
        file_reader_end.seek(std::io::SeekFrom::Start(seek_end))?;
        let take = (offsets.stop_eocd - offsets.start_cd - eocd_len) as u64;
        let mut file_reader_end = file_reader_end.take(take);
        copy(&mut file_reader_end, writer)?;

        // copy end of central directory
        writer.write_all(&oecd_serialized)?;

        Ok(())
    }

    /// Sign the APK file with the given algorithm.
    /// # Errors
    /// Returns a string if the signing fails.
    #[cfg(feature = "signing")]
    #[cfg(feature = "hash")] // implied by "signing"
    pub fn sign_v2(
        &mut self,
        algo: &Algorithms,
        cert: &[u8],
        private_key: rsa::RsaPrivateKey,
    ) -> Result<(), std::io::Error> {
        use crate::{
            common::{
                AdditionalAttributes, Certificate, Certificates, Digest, Digests, PubKey,
                Signature, Signatures,
            },
            scheme_v2::{SignedData as SignedDataV2, Signer, Signers},
        };
        use rsa::pkcs8::EncodePublicKey;
        let public_key = private_key.to_public_key();
        let pubkey = public_key
            .to_public_key_der()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let pubkey = pubkey.into_vec();
        let digest = self.digest(algo)?;

        let signed_data = SignedDataV2::new(
            Digests::new(vec![Digest::new(algo.clone(), digest)]),
            Certificates::new(vec![Certificate::new(cert.to_vec())]),
            AdditionalAttributes::new(vec![]),
        );

        let signed_data_serialized = signed_data.to_u8();
        let to_sign = &signed_data_serialized.get(4..).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid signed data")
        })?;
        let signature = algo
            .sign(private_key, to_sign)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let one_signer = Signer::new(
            signed_data,
            Signatures::new(vec![Signature::new(algo.clone(), signature)]),
            PubKey::new(pubkey),
        );

        let mut signing_block =
            SigningBlock::new_with_padding(vec![ValueSigningBlock::new_v2(Signers::new(vec![
                one_signer,
            ]))])?;
        let eocd = self.find_eocd()?;
        signing_block.offset_by(eocd.cd_offset as usize);

        self.sig = Some(signing_block);
        Ok(())
    }
}
