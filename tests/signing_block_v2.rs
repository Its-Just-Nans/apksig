include!("./raw_signing_block_v2.rs");

mod test {

    use super::*;
    use apksig::{
        common::{
            AdditionalAttributes, Certificate, Certificates, Digest, Digests, PubKey, Signature,
            Signatures,
        },
        scheme_v2::{SignedData, Signer, Signers},
        signing_block::{algorithms::Algorithms, RawData, VERITY_PADDING_BLOCK_ID},
        utils::MyReader,
        SignatureSchemeV2, SigningBlock, ValueSigningBlock, MAGIC, MAGIC_LEN,
        SIGNATURE_SCHEME_V2_BLOCK_ID,
    };

    #[test]
    fn test_constants() {
        let magic_vec = [
            65, 80, 75, 32, 83, 105, 103, 32, 66, 108, 111, 99, 107, 32, 52, 50,
        ];
        assert_eq!(MAGIC, &magic_vec);
        assert_eq!(MAGIC_LEN, 16);
    }

    #[test]
    fn test_signing_block() {
        let sig = SigningBlock::from_u8(&BLOCK[..]);
        let sig = sig.unwrap();
        assert_eq!(&sig.magic, MAGIC);
        let content_size = BLOCK.len() - 8 - 8 - MAGIC_LEN; // two u64 (8 bytes) and magic_len (64 bytes)
        assert_eq!(sig.content_size, content_size);
        assert_eq!(sig.file_offset_start, 0);
        assert_eq!(sig.file_offset_end, BLOCK.len());
        assert_eq!(sig.size_of_block_start, sig.size_of_block_end);
        assert_eq!(sig.content.len(), 2);
        if let ValueSigningBlock::SignatureSchemeV2Block(block) = &sig.content[0] {
            assert_eq!(block.size, 1314);
            assert_eq!(block.id, 0x7109871a);
            assert_eq!(block.signers.signers_data.len(), 1);
            let signer = &block.signers.signers_data[0];
            assert_eq!(signer.size, 1302);
            assert_eq!(signer.signed_data.digests.digests_data.len(), 1);
            assert_eq!(signer.signed_data.certificates.certificates_data.len(), 1);
            assert_eq!(
                signer
                    .signed_data
                    .additional_attributes
                    .additional_attributes_data
                    .len(),
                0
            );
            assert_eq!(signer.signatures.size, 268);
            assert_eq!(signer.signatures.signatures_data.len(), 1);
            assert_eq!(signer.pub_key.size, 294);
            assert_eq!(signer.pub_key.data.len(), 294);
        } else {
            panic!(
                "Expected ValueSigningBlock::SignatureSchemeV2Block() but got {:?}",
                sig.content[0]
            );
        }
        if let ValueSigningBlock::BaseSigningBlock(block) = &sig.content[1] {
            assert_eq!(block.size, 2734);
            assert_eq!(block.id, 0x42726577); // padding block
        } else {
            panic!(
                "Expected ValueSigningBlock::BaseSigningBlock() but got {:?}",
                sig.content[1]
            );
        }
    }

    #[test]
    fn test_serilization() {
        let sig = SigningBlock::from_u8(&BLOCK);
        let sig = sig.unwrap();
        let scheme_block = match &sig.content[0] {
            ValueSigningBlock::SignatureSchemeV2Block(block) => block,
            _ => panic!("Expected ValueSigningBlock::SignatureSchemeV2Block()"),
        };

        let signer = &scheme_block.signers.signers_data[0];

        let signed_data = &signer.signed_data;

        let digest = &signed_data.digests.digests_data[0];
        let digest_serialized = digest.to_u8();
        assert_eq!(digest.size, 40);
        assert_eq!(digest_serialized.len(), 40 + 4);
        let parse_digest = Digest::parse(&mut MyReader::new(&digest_serialized));
        assert!(parse_digest.is_ok());

        let digests = &signed_data.digests;
        let digests_serialized = digests.to_u8();
        assert_eq!(digests.size, 44);
        assert_eq!(digests_serialized.len(), 44 + 4);
        let parse_digests = Digests::parse(&mut MyReader::new(&digests_serialized));
        assert!(parse_digests.is_ok());

        let certificate = &signed_data.certificates.certificates_data[0];
        let certificate_serialized = certificate.to_u8();
        assert_eq!(certificate.size, 664);
        assert_eq!(certificate_serialized.len(), 664 + 4);
        let parse_certificate = Certificate::parse(&mut MyReader::new(&certificate_serialized));
        assert!(parse_certificate.is_ok());

        let certificates = &signed_data.certificates;
        let certificates_serialized = certificates.to_u8();
        assert_eq!(certificates.size, 668);
        assert_eq!(certificates_serialized.len(), 668 + 4);
        let parse_certificates = Certificates::parse(&mut MyReader::new(&certificates_serialized));
        assert!(parse_certificates.is_ok());

        let additional_attributes = &signed_data.additional_attributes;
        let additional_attributes_serialized = additional_attributes.to_u8();
        assert_eq!(additional_attributes.size, 0);
        assert_eq!(additional_attributes_serialized.len(), 4);
        let parse_additional_attributes =
            AdditionalAttributes::parse(&mut MyReader::new(&additional_attributes_serialized));
        assert!(parse_additional_attributes.is_ok());

        let signed_data_serialized = signed_data.to_u8();
        assert_eq!(signed_data.size, 728);
        assert_eq!(signed_data_serialized.len(), 728 + 4);
        let parse_signed_data = SignedData::parse(&mut MyReader::new(&signed_data_serialized));
        assert!(parse_signed_data.is_ok());

        let signatures = &signer.signatures;

        assert_eq!(signatures.signatures_data.len(), 1);
        let signature = &signatures.signatures_data[0];
        let signature_serialized = signature.to_u8();
        assert_eq!(signature_serialized.len(), 264 + 4);
        let parse_signature = Signature::parse(&mut MyReader::new(&signature_serialized));
        assert!(parse_signature.is_ok());

        let signatures_serialized = signatures.to_u8();
        assert_eq!(signatures_serialized.len(), 268 + 4);
        let parse_signatures = Signatures::parse(&mut MyReader::new(&signatures_serialized));
        assert!(parse_signatures.is_ok());

        let key = signer.pub_key.to_u8();
        assert_eq!(key.len(), 294 + 4);
        let parse_key = PubKey::parse(&mut MyReader::new(&key));
        assert!(parse_key.is_ok());

        let serialized_signer = signer.to_u8();
        assert_eq!(signer.size, 1302);
        assert_eq!(serialized_signer.len(), 1302 + 4);
        let parse_signer = Signer::parse(&mut MyReader::new(&serialized_signer));
        assert!(parse_signer.is_ok());

        let serialized_scheme_block = scheme_block.to_u8();
        assert_eq!(scheme_block.size, 1314);
        assert_eq!(serialized_scheme_block.len(), 1314 + 8); // 8 bytes for size of u64
        let new_block = sig.to_u8();
        assert_eq!(sig.content.len(), 2);

        assert_eq!(sig.content_size, sig.content_to_u8().len());

        assert_eq!(new_block.len(), BLOCK.len());
        assert_eq!(&new_block[..], &BLOCK[..]);
    }

    #[test]
    fn test_create_signing_block_by_hand() {
        // value needed to create the signing block
        let digest_signature_algorithm_id = Algorithms::from(0x103);
        let digest = DIGEST.to_vec();
        let signature_signature_algorithm_id = Algorithms::from(0x103);
        let signature = SIGNATURE.to_vec();
        let pubkey = PUBKEY.to_vec();
        let certificate = CERTIFICATE.to_vec();

        let content = vec![
            ValueSigningBlock::SignatureSchemeV2Block(SignatureSchemeV2 {
                size: 1314,
                id: SIGNATURE_SCHEME_V2_BLOCK_ID,
                signers: Signers {
                    size: 1306,
                    signers_data: vec![Signer {
                        size: 1302,
                        signed_data: SignedData {
                            size: 728, // 724 + 4 bytes padding
                            digests: Digests {
                                size: 44,
                                digests_data: vec![Digest {
                                    size: 40,
                                    signature_algorithm_id: digest_signature_algorithm_id,
                                    digest,
                                }],
                            },
                            certificates: Certificates {
                                size: 668,
                                certificates_data: vec![Certificate {
                                    size: 664,
                                    certificate,
                                }],
                            },
                            additional_attributes: AdditionalAttributes {
                                size: 0,
                                additional_attributes_data: vec![],
                            },
                            // see docs for more info
                            // the new method SignedData::new() is recommended
                            _private_auto_padding_fix: true,
                        },
                        signatures: Signatures {
                            size: 268,
                            signatures_data: vec![Signature {
                                size: 264,
                                signature_algorithm_id: signature_signature_algorithm_id,
                                signature,
                            }],
                        },
                        pub_key: PubKey {
                            size: 294,
                            data: pubkey,
                        },
                    }],
                },
            }),
            ValueSigningBlock::BaseSigningBlock(RawData {
                size: 2734,
                id: VERITY_PADDING_BLOCK_ID,
                data: vec![0; 2730],
            }),
        ];
        let sig = SigningBlock {
            magic: MAGIC.to_owned(),
            content_size: content.iter().map(|c| c.to_u8().len()).sum(),
            file_offset_start: 0,
            file_offset_end: 0,
            size_of_block_start: 4088,
            size_of_block_end: 4088,
            content,
        };

        let serialized_sig = sig.to_u8();

        for (i, c) in BLOCK.iter().enumerate() {
            assert_eq!(c, &serialized_sig[i]);
        }

        assert_eq!(&BLOCK[..], &serialized_sig);
    }

    #[test]
    fn test_create_signing_block_with_builders() {
        // value needed to create the signing block
        let signature_algorithm_id = Algorithms::from(0x103);
        let digest = DIGEST.to_vec();
        let signature = SIGNATURE.to_vec();
        let certificate = CERTIFICATE.to_vec();
        let pubkey = PUBKEY.to_vec();
        // technically you can extract the pubkey from the certificate
        // see test_certificate.rs for more info

        let scheme_v2 = ValueSigningBlock::new_v2(Signers::new(vec![Signer::new(
            SignedData::new(
                Digests::new(vec![Digest::new(
                    signature_algorithm_id.clone(),
                    digest.clone(),
                )]),
                Certificates::new(vec![Certificate::new(certificate)]),
                AdditionalAttributes::new(vec![]),
            ),
            Signatures::new(vec![Signature::new(signature_algorithm_id, signature)]),
            PubKey::new(pubkey),
        )]));
        let sig = SigningBlock::new_with_padding(vec![scheme_v2]).unwrap();

        let serialized_sig = sig.to_u8();

        for (i, original) in BLOCK.iter().enumerate() {
            assert_eq!(original, &serialized_sig[i]);
        }

        assert_eq!(&BLOCK[..], &serialized_sig);
    }
}
