mod test {

    include!("./raw_signing_block_v2.rs");

    #[cfg(feature = "certificate")]
    #[cfg(feature = "hash")]
    #[test]
    fn test_certificate() {
        use apksig::common::Certificate;
        use std::fmt::Write;
        let certificate = Certificate::new(CERTIFICATE.to_vec());

        let issuer = certificate.get_issuer().unwrap();
        let sha256 = certificate.sha256_cert();
        let md5 = certificate.md5_cert();
        let sha1 = certificate.sha1_cert();
        assert_eq!(issuer, "n4n5");
        let sha256_hex = sha256.iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        });
        assert_eq!(sha256, SHA256_CERT);
        assert_eq!(sha256_hex, SHA256_CERT_STR);
        let md5_hex = md5.iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        });
        assert_eq!(md5, MD5_CERT);
        assert_eq!(md5_hex, MD5_CERT_STR);
        let sha1_hex = sha1.iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        });
        assert_eq!(sha1, SHA1_CERT);
        assert_eq!(sha1_hex, SHA1_CERT_STR);
    }

    #[cfg(feature = "certificate")]
    #[test]
    fn test_build_with_certificate() {
        use apksig::{
            common::{
                AdditionalAttributes, Certificate, Certificates, Digest, Digests, PubKey,
                Signature, Signatures,
            },
            scheme_v2::{SignedData, Signer, Signers},
            signing_block::algorithms::Algorithms,
            SigningBlock, ValueSigningBlock,
        };
        use x509_parser::prelude::{FromDer, X509Certificate};

        // value needed to create the signing block
        let cert = CERTIFICATE.to_vec();
        let signature_algorithm_id = Algorithms::from(0x103);
        let digest = DIGEST.to_vec();
        let signature = SIGNATURE.to_vec();

        // extract public key from certificate
        let certificate = Certificate::new(cert);
        let cert = X509Certificate::from_der(&certificate.certificate).unwrap();
        let pubkey = cert.1.public_key().raw.to_vec();

        // start block creation
        let signed_data = SignedData::new(
            Digests::new(vec![Digest::new(
                signature_algorithm_id.clone(),
                digest.clone(),
            )]),
            Certificates::new(vec![certificate]),
            AdditionalAttributes::new(vec![]),
        );

        let content = ValueSigningBlock::new_v2(Signers::new(vec![Signer::new(
            signed_data,
            Signatures::new(vec![Signature::new(signature_algorithm_id, signature)]),
            PubKey::new(pubkey),
        )]));

        let sig = SigningBlock::new_with_padding(vec![content]).unwrap();

        let serialized_sig = sig.to_u8();

        for (i, c) in BLOCK.iter().enumerate() {
            assert_eq!(c, &serialized_sig[i]);
        }

        assert_eq!(&BLOCK[..], &serialized_sig);
    }
}
