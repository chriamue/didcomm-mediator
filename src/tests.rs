use super::*;
use didcomm_rs::{
    crypto::{CryptoAlgorithm, SignatureAlgorithm},
    Message,
};
use ed25519_dalek::Keypair;
use rand_core::OsRng;

#[test]
fn test_jwe() {
    let sign_keypair = ed25519_dalek::Keypair::generate(&mut OsRng);
    let alice_keypair = ed25519_dalek::Keypair::generate(&mut OsRng);
    let bob_keypair = ed25519_dalek::Keypair::generate(&mut OsRng);

    let alice_private = alice_keypair.secret.as_bytes();
    let bobs_private = bob_keypair.secret.as_bytes();

    let alice_public = alice_keypair.public.as_bytes();
    let bobs_public = alice_keypair.public.as_bytes();

    let body = r#"{"foo":"bar"}"#;
    let message = Message::new()
        .body(body)
        .as_flat_jwe(&CryptoAlgorithm::XC20P, Some(bobs_public.to_vec()))
        .kid(&hex::encode(sign_keypair.public.to_bytes()));

    let jwe_string = message
        .seal_signed(
            alice_private,
            Some(vec![Some(bobs_public.to_vec())]),
            SignatureAlgorithm::EdDsa,
            &sign_keypair.to_bytes(),
        )
        .unwrap();

    let received = Message::receive(
        &jwe_string,
        Some(bobs_private),
        Some(alice_public.to_vec()),
        None,
    );

    assert!(&received.is_ok());
    let received = received.unwrap();
    let sample_body: Value = serde_json::from_str(body).unwrap();
    let received_body: Value = serde_json::from_str(&received.get_body().unwrap()).unwrap();
    assert_eq!(sample_body.to_string(), received_body.to_string(),);
}

#[test]
fn test_jwe_with_did_key() {}
