mod test {

    include!("./raw_signing_block_v2.rs");
    #[cfg(feature = "signing")]
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

        let data = &signed_data.to_u8()[4..];

        let verification = algorithm.verify(&PUBKEY, data, &SIGNATURE);
        verification.unwrap();
    }
}
