use super::*;
use arrayref::array_ref;
use base58::FromBase58;
use did_key::{generate, Ed25519KeyPair, KeyPair, X25519KeyPair, CONFIG_JOSE_PUBLIC};
use didcomm_rs::{
    crypto::{CryptoAlgorithm, SignatureAlgorithm},
    Message,
};
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

#[test]
fn test_jwe() {
    let sign_keypair = ed25519_dalek::Keypair::generate(&mut OsRng);
    let alice_keypair = ed25519_dalek::Keypair::generate(&mut OsRng);
    let bob_keypair = ed25519_dalek::Keypair::generate(&mut OsRng);

    let alice_private = alice_keypair.secret.as_bytes();
    let bobs_private = bob_keypair.secret.as_bytes();

    let alice_public = &alice_keypair.public.as_bytes();
    let bobs_public = &alice_keypair.public.as_bytes();

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
fn test_jwe_with_did_key() {
    let sign_keypair = ed25519_dalek::Keypair::generate(&mut OsRng);
    let seed_alice = "6QN8DfuN9hjgHgPvLXqgzqYE3jRRGRrmJQZkd5tL8paR";
    let seed_bob = "HBTcN2MrXNRj9xF9oi8QqYyuEPv3JLLjQKuEgW9oxVKP";
    let alice_keypair = generate::<X25519KeyPair>(Some(&seed_alice.from_base58().unwrap()));
    let bob_keypair = generate::<X25519KeyPair>(Some(&seed_bob.from_base58().unwrap()));

    let alice_private = alice_keypair.private_key_bytes();
    let bobs_private = bob_keypair.private_key_bytes();

    let alice_public = alice_keypair.public_key_bytes();
    let bobs_public = alice_keypair.public_key_bytes();

    let body = r#"{"foo":"bar"}"#;
    let message = Message::new()
        .from("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
        .to(&["did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"])
        .body(body)
        .as_flat_jwe(&CryptoAlgorithm::XC20P, Some(bobs_public.to_vec()))
        .kid(&hex::encode(sign_keypair.public.to_bytes()));

    let jwe_string = message
        .seal_signed(
            &alice_private,
            Some(vec![Some(bobs_public.to_vec())]),
            SignatureAlgorithm::EdDsa,
            &sign_keypair.to_bytes(),
        )
        .unwrap();

    let received = Message::receive(
        &jwe_string,
        Some(&bobs_private),
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
fn test_keypairs() {
    let seed = "6QN8DfuN9hjgHgPvLXqgzqYE3jRRGRrmJQZkd5tL8paR";
    let alice_private = seed.from_base58().unwrap();

    let alice_secret_key: StaticSecret =
        StaticSecret::from(array_ref!(alice_private, 0, 32).to_owned());

    let alice_public = PublicKey::from(&alice_secret_key);

    let did_key_alice = did_key::generate::<X25519KeyPair>(Some(&seed.from_base58().unwrap()));
    assert_eq!(alice_private, did_key_alice.private_key_bytes());
    println!(
        "private {:?} / {:?}",
        alice_private,
        did_key_alice.private_key_bytes()
    );
    println!(
        "public {:?} / {:?}",
        alice_public,
        did_key_alice.public_key_bytes()
    );
    assert_eq!(
        alice_public.to_bytes().to_vec(),
        did_key_alice.public_key_bytes().to_vec()
    );
}
