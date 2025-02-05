mod test {

    include!("./raw_signing_block_v2.rs");

    #[cfg(feature = "hash")]
    #[test]
    fn test_digest() {
        use apksig::{
            signing_block::{
                algorithms::Algorithms,
                digest::{digest_apk, find_eocd, FileOffsets},
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
        let eocd = find_eocd(&mut file, file_len).unwrap();
        let algo = Algorithms::RSASSA_PKCS1_v1_5_256;
        let offsets = FileOffsets {
            start_content: 0,
            stop_content: sig.file_offset_start,
            start_cd: sig.file_offset_end,
            stop_cd: eocd.file_offset,
            start_eocd: eocd.file_offset,
            stop_eocd: file_len,
        };
        let digest = digest_apk(&mut file, &offsets, &algo).unwrap();
        assert_eq!(digest.len(), 32);
        assert_eq!(digest, DIGEST[..]);
    }

    #[cfg(feature = "hash")]
    #[test]
    fn test_digest_raw_apk() {
        use apksig::{
            signing_block::{
                algorithms::Algorithms,
                digest::{digest_apk, find_eocd, FileOffsets},
            },
            SigningBlock,
        };
        use std::{
            fs::{read, File},
            os::unix::fs::MetadataExt,
            path::Path,
        };
        let file = file!();
        let dir = Path::new(file).parent().unwrap();
        let apk = dir.join("sms2call-1.0.8.apk");
        let mut file = File::open(&apk).unwrap();
        let file_len = file.metadata().unwrap().size() as usize;
        let sig = SigningBlock::from_reader(&mut file, file_len, 0).unwrap();

        let start_sig = sig.file_offset_start;
        let end_sig = sig.file_offset_end;
        let size_sig = end_sig - start_sig;
        // println!("{:?}", (start_sig, end_sig, size_sig));

        let full_raw_file = read(apk).unwrap();
        assert_eq!(full_raw_file.len(), file_len);

        let apk_without_signature =
            [&full_raw_file[..start_sig], &full_raw_file[end_sig..]].concat();
        // verify that the signature was removed
        // so the size of the file should be the original size - size of the signature
        let file_len = file_len - size_sig;
        assert_eq!(apk_without_signature.len(), file_len);

        // From now, our file is a raw APK as Vec<u8>, we can use a cursor to wrap it
        // cursor acts as Read + Seek
        let mut cursor = std::io::Cursor::new(&apk_without_signature);
        let eocd = find_eocd(&mut cursor, file_len).unwrap();

        // see docs of FileOffsets for more details
        let offsets = FileOffsets {
            start_content: 0,
            stop_content: start_sig,
            start_cd: start_sig,
            stop_cd: eocd.file_offset,
            start_eocd: eocd.file_offset,
            stop_eocd: file_len,
        };

        let algo = Algorithms::RSASSA_PKCS1_v1_5_256;
        let digest = digest_apk(&mut cursor, &offsets, &algo).unwrap();
        assert_eq!(digest.len(), 32);
        assert_eq!(digest, DIGEST[..]);
    }
}
