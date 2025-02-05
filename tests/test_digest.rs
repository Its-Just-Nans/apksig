mod test {

    include!("./raw_signing_block_v2.rs");

    #[cfg(feature = "certificate")]
    #[cfg(feature = "hash")]
    #[test]
    fn test_digest() {
        use apksig::{
            signing_block::{
                algorithms::Algorithms,
                digest::{digest_apk, find_oecd},
            },
            SigningBlock,
        };
        use std::{fs::File, os::unix::fs::MetadataExt, path::Path};

        let file = file!();
        let dir = Path::new(file).parent().unwrap();
        let apk = dir.join("sms2call-1.0.8.apk");
        let mut file = File::open(apk).unwrap();
        let file_len = file.metadata().unwrap().size() as usize;
        let sig = SigningBlock::from_reader(&mut file, file_len, 0).unwrap();
        // find the eocd of file
        let eocd = find_oecd(&mut file).unwrap();
        let algo = Algorithms::RSASSA_PKCS1_v1_5_256;
        let offsets = (
            sig.file_offset_start,
            sig.file_offset_end,
            eocd.file_offset,
            file_len,
        );
        let digest = digest_apk(&mut file, offsets, &algo).unwrap();
        assert_eq!(digest.len(), 32);
        assert_eq!(digest, DIGEST[..]);
    }
}
