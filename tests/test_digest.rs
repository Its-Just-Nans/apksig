#![cfg(feature = "hash")]

mod test {

    include!("./raw_signing_block_v2.rs");
    use apksig::Apk;
    use apksig::{
        signing_block::{algorithms::Algorithms, digest::digest_apk},
        zip::{find_eocd, FileOffsets},
        SigningBlock,
    };
    use std::{
        fs::{read, File},
        os::unix::fs::MetadataExt,
        path::Path,
    };

    #[test]
    fn test_digest() {
        let file = file!();
        let dir = Path::new(file).parent().unwrap();
        let apk = dir.join("sms2call-1.0.8.apk");
        let mut file = File::open(apk).unwrap();
        let file_len = file.metadata().unwrap().size() as usize;
        let sig = SigningBlock::from_reader(&mut file, file_len, 0).unwrap();
        // find the eocd of file
        let eocd = find_eocd(&mut file, file_len).unwrap();
        let algo = Algorithms::RSASSA_PKCS1_v1_5_256;

        // see docs of FileOffsets for more details
        let offsets = FileOffsets::new(
            sig.file_offset_start,
            sig.file_offset_end,
            eocd.file_offset,
            file_len,
        );
        let digest = digest_apk(&mut file, &offsets, &algo).unwrap();
        assert_eq!(digest.len(), 32);
        assert_eq!(digest, DIGEST[..]);
    }

    fn get_raw_apk() -> Vec<u8> {
        let file = file!();
        let dir = Path::new(file).parent().unwrap();
        let apk = dir.join("sms2call-1.0.8.apk");
        let mut file = File::open(&apk).unwrap();
        let file_len = file.metadata().unwrap().size() as usize;
        let sig = SigningBlock::from_reader(&mut file, file_len, 0).unwrap();

        let start_sig = sig.file_offset_start;
        let end_sig = sig.file_offset_end;
        let size_sig = end_sig - start_sig;

        let full_raw_file = read(apk).unwrap();
        assert_eq!(full_raw_file.len(), file_len);

        let mut apk_without_signature =
            [&full_raw_file[..start_sig], &full_raw_file[end_sig..]].concat();

        // verify that the signature was removed
        // so the size of the file should be the original size - size of the signature
        let file_len = file_len - size_sig;
        assert_eq!(apk_without_signature.len(), file_len);

        // modify the zip cd_offset
        const CD_OFFSET: u32 = 4888772;
        apk_without_signature[file_len - 6..file_len - 2]
            .copy_from_slice(CD_OFFSET.to_le_bytes().as_ref());

        // let out = dir.join("sms2call-1.0.8_no_sig.apk");
        // std::fs::write(&out, &apk_without_signature).unwrap();
        apk_without_signature
    }

    #[test]
    fn test_digest_raw_apk() {
        let apk_without_signature = get_raw_apk();
        let file_len = apk_without_signature.len();

        // From now, our file is a raw APK as Vec<u8>, we can use a cursor to wrap it
        // cursor acts as Read + Seek
        let mut cursor = std::io::Cursor::new(&apk_without_signature);
        let eocd = find_eocd(&mut cursor, file_len).unwrap();

        // see docs of FileOffsets for more details
        let stop_content = eocd.cd_offset as usize;
        let offsets = FileOffsets::without_signature(stop_content, eocd.file_offset, file_len);

        let algo = Algorithms::RSASSA_PKCS1_v1_5_256;
        let digest = digest_apk(&mut cursor, &offsets, &algo).unwrap();
        assert_eq!(digest.len(), 32);
        assert_eq!(digest, DIGEST[..]);
    }

    #[test]
    fn test_digest_with_apk_struct() {
        get_raw_apk();
        let file = file!();
        let dir = Path::new(file).parent().unwrap();
        let apk_path = dir.join("sms2call-1.0.8.apk");
        let apk = Apk::new(apk_path).unwrap();
        let algo = Algorithms::RSASSA_PKCS1_v1_5_256;
        let digest = apk.digest(&algo).unwrap();
        assert_eq!(digest.len(), 32);
        assert_eq!(digest, DIGEST[..]);
    }

    #[test]
    fn test_digest_raw_with_apk_struct() {
        get_raw_apk();
        let file = file!();
        let dir = Path::new(file).parent().unwrap();
        let apk_path = dir.join("sms2call-1.0.8_no_sig.apk");
        let apk = Apk::new_raw(apk_path).unwrap();
        let algo = Algorithms::RSASSA_PKCS1_v1_5_256;
        let digest = apk.digest(&algo).unwrap();
        assert_eq!(digest.len(), 32);
        assert_eq!(digest, DIGEST[..]);
    }
}
