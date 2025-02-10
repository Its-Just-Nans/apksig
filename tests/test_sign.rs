#![cfg(feature = "signing")]

mod test {
    use std::path::Path;

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
        let signature_algorithm_id = Algorithms::RSASSA_PKCS1_v1_5_256;

        let mut rng = rand::thread_rng();
        let bits = 2048;

        let private_key = rsa::RsaPrivateKey::new(&mut rng, bits).unwrap();

        apk.sign_v2(&signature_algorithm_id, &cert, private_key)
            .unwrap();

        let sig = apk.get_signing_block().unwrap();
        let sig_serialized = sig.to_u8();
        assert_eq!(sig_serialized.len(), 4096);
    }
}
