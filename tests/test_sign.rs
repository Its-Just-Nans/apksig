#![cfg(feature = "signing")]

mod test {
    use std::{fs::read, path::Path};

    include!("./raw_signing_block_v2.rs");

    #[test]
    fn test_verify_signature() {
        use apksig::{
            common::{AdditionalAttributes, Certificate, Certificates, Digest, Digests},
            scheme_v2::SignedData,
            Algorithms,
        };

        let algorithm = Algorithms::RSASSA_PKCS1_v1_5_256;
        let digest = DIGEST.to_vec();
        let certificate = CERTIFICATE.to_vec();

        let signed_data = SignedData::new(
            Digests::new(vec![Digest::new(algorithm.clone(), digest.clone())]),
            Certificates::new(vec![Certificate::new(certificate)]),
            AdditionalAttributes::new(vec![]),
        );
        // remove the first 4 bytes of the signed data (length of the signed data)
        let data = &signed_data.to_u8()[4..];

        let verification = algorithm.verify(&PUBKEY, data, &SIGNATURE);
        verification.unwrap();
    }

    #[test]
    fn test_verify_with_apk_struct() {
        use apksig::Apk;
        use std::path::Path;

        let file = file!();
        let dir = Path::new(file).parent().unwrap();
        let apk_path = dir.join("sms2call-1.0.8.apk");
        let apk = Apk::new(apk_path).unwrap();
        apk.verify().unwrap();

        let apk_path = dir.join("de.kaffeemitkoffein.imagepipe_51.apk");
        let apk = Apk::new(apk_path).unwrap();
        assert!(apk.verify().is_err()); // for now v3 verification is not supported
    }

    #[test]
    fn test_sign_with_apk_struct() {
        use apksig::signing_block::algorithms::Algorithms;

        use apksig::Apk;
        let file = file!();
        let dir = Path::new(file).parent().unwrap();
        let apk_path = dir.join("sms2call-1.0.8_no_sig.apk");

        let mut apk = Apk::new_raw(apk_path).unwrap(); // create with new_raw()

        let cert = CERTIFICATE.to_vec();
        let algo = Algorithms::RSASSA_PKCS1_v1_5_256;

        let mut rng = rand::thread_rng(); // rand v0.8.0
        let bits = 512; // force reduce the bits for faster testing

        let private_key = rsa::RsaPrivateKey::new(&mut rng, bits).unwrap();

        apk.sign_v2(&algo, &cert, private_key).unwrap();

        let sig = apk.get_signing_block().unwrap();
        let sig_serialized = sig.to_u8();
        assert_eq!(sig_serialized.len(), 4096);
    }

    // ignore because the private key is not available
    #[ignore]
    #[test]
    fn test_sign_from_keystore() {
        use apksig::signing_block::algorithms::Algorithms;
        use rsa::pkcs8::DecodePrivateKey;

        use apksig::Apk;
        let file = file!();
        let dir = Path::new(file).parent().unwrap();
        let apk_path = dir.join("sms2call-1.0.8_no_sig.apk");

        let mut apk = Apk::new_raw(apk_path).unwrap(); // create with new_raw()

        // see more at <https://n4n5.dev/articles/work-with-apk/>
        // ```sh
        // keytool -keystore ~/path/to/keystore -exportcert -alias key_alias -file tests/keystore_cert.der
        // ```
        // from test::test_certificate_from_keystore()
        let cert = include_bytes!("./keystore_cert.der").to_vec();
        let algo = Algorithms::RSASSA_PKCS1_v1_5_256;

        // you need to convert your jks keystore to pkcs12
        // then export the private key in private.key
        // ```sh
        // openssl pkcs12 -in ~/path/to/keystore.p12 -nodes -nocerts -out private.key
        // ```
        // see more at <https://n4n5.dev/articles/work-with-apk/>
        // let pkcs1_pem = include_str!("../private.key");
        let pkcs1_pem = "";

        let private_key = rsa::RsaPrivateKey::from_pkcs8_pem(pkcs1_pem).unwrap();

        // this method will generate a new signature block inside the Apk struct
        // therefor the Apk struct need to be mutable
        apk.sign_v2(&algo, &cert, private_key).unwrap();

        // the Apk struct has now a signing block
        let sig = apk.get_signing_block().unwrap();
        let sig_serialized = sig.to_u8();
        assert_eq!(sig_serialized.len(), 4096);
        assert_eq!(BLOCK.to_vec(), sig_serialized);

        let mut writer = Vec::new();
        apk.write_with_signature(&mut writer).unwrap();

        let base_apk = read(dir.join("sms2call-1.0.8.apk")).unwrap();

        assert_eq!(writer, base_apk);
    }
}
