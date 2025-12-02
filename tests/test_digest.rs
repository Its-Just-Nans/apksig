#![cfg(feature = "hash")]

mod test {

    include!("./raw_signing_block_v2.rs");
    use apksig::Apk;
    use apksig::{
        SigningBlock,
        signing_block::{algorithms::Algorithms, digest::digest_apk},
        zip::{FileOffsets, find_eocd},
    };
    use std::{
        fs::{File, read},
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

    #[test]
    fn test_digest_raw_apk() {
        let file = file!();
        let dir = Path::new(file).parent().unwrap();
        let apk_path = dir.join("sms2call-1.0.8.apk");
        let apk = Apk::new(apk_path).unwrap();
        let apk_without_signature = apk.get_raw_apk().unwrap();
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
    fn test_raw_apk_creation() {
        let file = file!();
        let dir = Path::new(file).parent().unwrap();
        let apk_path = dir.join("sms2call-1.0.8.apk");
        let apk = Apk::new(apk_path).unwrap();
        let apk_without_signature = apk.get_raw_apk().unwrap();

        let raw_apk_file = read(dir.join("sms2call-1.0.8_no_sig.apk")).unwrap();

        assert_eq!(apk_without_signature.len(), raw_apk_file.len());
        assert_eq!(apk_without_signature, raw_apk_file);
    }

    #[test]
    fn test_digest_with_apk_struct() {
        let file = file!();
        let dir = Path::new(file).parent().unwrap();
        let apk_path = dir.join("sms2call-1.0.8.apk");

        let apk = Apk::new(apk_path).unwrap(); // create with new()
        let algo = Algorithms::RSASSA_PKCS1_v1_5_256;
        let digest = apk.digest(&algo).unwrap();

        assert_eq!(digest.len(), 32);
        assert_eq!(digest, DIGEST[..]);
    }

    #[test]
    fn test_digest_raw_with_apk_struct() {
        let file = file!();
        let dir = Path::new(file).parent().unwrap();
        let apk_path = dir.join("sms2call-1.0.8_no_sig.apk");

        let apk = Apk::new_raw(apk_path).unwrap(); // create with new_raw()
        let algo = Algorithms::RSASSA_PKCS1_v1_5_256;
        let digest = apk.digest(&algo).unwrap();

        assert_eq!(digest.len(), 32);
        assert_eq!(digest, DIGEST[..]);
    }
}
