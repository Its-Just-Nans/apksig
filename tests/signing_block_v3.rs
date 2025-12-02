//! https://codeberg.org/Starfish/Imagepipe

mod test {
    use apksig::{
        MAGIC, MAGIC_LEN, SIGNATURE_SCHEME_V2_BLOCK_ID, SIGNATURE_SCHEME_V3_BLOCK_ID, SigningBlock,
        ValueSigningBlock,
    };
    use std::io::Read;
    use std::{fs::File, path::Path};

    #[test]
    fn test_app_image_pipe() {
        let file = file!();
        let dir = Path::new(file).parent().unwrap();
        let apk = dir.join("de.kaffeemitkoffein.imagepipe_51.apk");
        let mut reader = File::open(apk).unwrap();
        let file_len = reader.metadata().unwrap().len() as usize;
        let sig = SigningBlock::from_reader(&mut reader, file_len, 0);
        let sig = sig.unwrap();
        assert_eq!(&sig.magic, MAGIC);
        let start = 552960;
        let end = 557056;
        let size = end - start - MAGIC_LEN - 8 - 8;
        assert_eq!(sig.content_size, size);
        assert_eq!(sig.file_offset_start, start);
        assert_eq!(sig.file_offset_end, end);
        assert_eq!(sig.size_of_block_start, sig.size_of_block_end);
        assert_eq!(sig.content.len(), 3);
        if let ValueSigningBlock::SignatureSchemeV2Block(block) = &sig.content[0] {
            assert_eq!(block.size, 1849);
            assert_eq!(block.id, SIGNATURE_SCHEME_V2_BLOCK_ID);
            assert_eq!(block.signers.signers_data.len(), 1);
            let signer = &block.signers.signers_data[0];
            assert_eq!(signer.size, 1837);
            assert_eq!(signer.signed_data.digests.digests_data.len(), 2);
            let digest = &signer.signed_data.digests.digests_data[0];
            assert_eq!(digest.size, 40);
            assert_eq!(digest.digest.len(), 32);
            let digest = &signer.signed_data.digests.digests_data[1];
            assert_eq!(digest.size, 48);
            assert_eq!(digest.digest.len(), 40);
            assert_eq!(signer.signed_data.certificates.certificates_data.len(), 1);
            let cert = &signer.signed_data.certificates.certificates_data[0];
            assert_eq!(cert.certificate.len(), 867);

            assert_eq!(
                signer
                    .signed_data
                    .additional_attributes
                    .additional_attributes_data
                    .len(),
                1
            );
            let attr = &signer
                .signed_data
                .additional_attributes
                .additional_attributes_data[0];
            assert_eq!(attr.size, 8);
            assert_eq!(attr.id, 3203395597);
            assert_eq!(attr.data.len(), 4);
            assert_eq!(attr.data, vec![3, 0, 0, 0]);

            assert_eq!(signer.signatures.signatures_data.len(), 2);
            let sig = &signer.signatures.signatures_data[0];
            assert_eq!(sig.size, 264);
            assert_eq!(sig.signature.len(), 256);
            let sig = &signer.signatures.signatures_data[1];
            assert_eq!(sig.size, 264);
            assert_eq!(sig.signature.len(), 256);

            assert_eq!(signer.pub_key.size, 294);
            assert_eq!(signer.pub_key.data.len(), 294);
        } else {
            panic!(
                "Expected ValueSigningBlock::SignatureSchemeV2Block() but got {:?}",
                sig.content[0]
            );
        }
        if let ValueSigningBlock::SignatureSchemeV3Block(block) = &sig.content[1] {
            assert_eq!(block.size, 1849);
            assert_eq!(block.id, SIGNATURE_SCHEME_V3_BLOCK_ID);
            assert_eq!(block.signers.signers_data.len(), 1);
            let signer = &block.signers.signers_data[0];
            assert_eq!(signer.size, 1837);
            assert_eq!(signer.signed_data.digests.digests_data.len(), 2);
            let digest = &signer.signed_data.digests.digests_data[0];
            assert_eq!(digest.size, 40);
            assert_eq!(digest.digest.len(), 32);
            let digest = &signer.signed_data.digests.digests_data[1];
            assert_eq!(digest.size, 48);
            assert_eq!(digest.digest.len(), 40);
            assert_eq!(signer.signed_data.certificates.certificates_data.len(), 1);
            let cert = &signer.signed_data.certificates.certificates_data[0];
            assert_eq!(cert.certificate.len(), 867);
            assert_eq!(
                signer
                    .signed_data
                    .additional_attributes
                    .additional_attributes_data
                    .len(),
                0
            );

            assert_eq!(signer.signatures.signatures_data.len(), 2);
            let sig = &signer.signatures.signatures_data[0];
            assert_eq!(sig.size, 264);
            assert_eq!(sig.signature.len(), 256);
            let sig = &signer.signatures.signatures_data[1];
            assert_eq!(sig.size, 264);
            assert_eq!(sig.signature.len(), 256);

            assert_eq!(signer.pub_key.size, 294);
            assert_eq!(signer.pub_key.data.len(), 294);
        } else {
            panic!(
                "Expected ValueSigningBlock::SignatureSchemeV3Block() but got {:?}",
                sig.content[2]
            );
        }
        if let ValueSigningBlock::BaseSigningBlock(block) = &sig.content[2] {
            assert_eq!(block.size, 342);
            assert_eq!(block.id, 0x42726577); // padding block
        } else {
            panic!(
                "Expected ValueSigningBlock::BaseSigningBlock() but got {:?}",
                sig.content[1]
            );
        }
    }

    #[test]
    fn test_scheme_v3_serialize() {
        let file = file!();
        let dir = Path::new(file).parent().unwrap();
        let apk = dir.join("de.kaffeemitkoffein.imagepipe_51.apk");
        let mut reader = File::open(apk).unwrap();
        let mut buffer_apk = Vec::new();
        reader.read_to_end(&mut buffer_apk).unwrap();

        let file_len = reader.metadata().unwrap().len() as usize;
        let sig = SigningBlock::from_reader(&mut reader, file_len, 0);
        let sig = sig.unwrap();

        let binary_block = buffer_apk[sig.file_offset_start..sig.file_offset_end].to_vec();
        assert_eq!(sig.to_u8(), binary_block);

        let sig_binary = SigningBlock::from_u8(&binary_block);
        let sig_binary = sig_binary.unwrap();
        assert_eq!(sig_binary.content_size, sig_binary.content_to_u8().len());

        assert_eq!(sig_binary.content_to_u8(), sig.content_to_u8());
        assert_eq!(sig_binary.content_to_u8().len(), sig.content_to_u8().len());

        assert_eq!(sig.to_u8(), sig_binary.to_u8());
    }
}
