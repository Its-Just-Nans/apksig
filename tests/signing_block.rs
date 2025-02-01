include!("./raw_signing_block_v2.rs");

mod test {

    use super::*;
    use apksig::{SigningBlock, ValueSigningBlock, MAGIC, MAGIC_LEN};

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
        let file_len = BLOCK.len();
        let reader = std::io::Cursor::new(&BLOCK[..]);
        let sig = SigningBlock::extract(reader, file_len, 0);
        assert!(sig.is_ok());
        let sig = sig.unwrap();
        assert_eq!(&sig.magic, MAGIC);
        let content_size = BLOCK.len() - 8 - 8 - MAGIC_LEN; // two u64 (8 bytes) and magic_len (64 bytes)
        assert_eq!(sig.content_size, content_size);
        assert_eq!(sig.file_offset_start, 0);
        assert_eq!(sig.file_offset_end, BLOCK.len());
        assert_eq!(sig.start_size, sig.end_size);
        assert_eq!(sig.content.len(), 2);
        if let ValueSigningBlock::SignatureSchemeV2Block(block) = &sig.content[0] {
            assert_eq!(block.size, 1314);
            assert_eq!(block.id, 0x7109871a);
            assert_eq!(block.signers.len(), 1);
            let signer = &block.signers[0];
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
            assert_eq!(signer.signatures.signatures_data.len(), 1);
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
}
