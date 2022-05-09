use super::*;
use arrayref::array_ref;
use base58::FromBase58;
use did_key::{generate, Ed25519KeyPair, X25519KeyPair};
use didcomm_rs::{
    crypto::{CryptoAlgorithm, SignatureAlgorithm},
    Message,
};
use x25519_dalek::{PublicKey, StaticSecret};

#[test]
fn test_jwe_with_did_key() {
    let seed_alice = "6QN8DfuN9hjgHgPvLXqgzqYE3jRRGRrmJQZkd5tL8paR";
    let seed_bob = "HBTcN2MrXNRj9xF9oi8QqYyuEPv3JLLjQKuEgW9oxVKP";

    let alice_keypair = generate::<X25519KeyPair>(Some(&seed_alice.from_base58().unwrap()));
    let bob_keypair = generate::<X25519KeyPair>(Some(&seed_bob.from_base58().unwrap()));

    let alice_private = alice_keypair.private_key_bytes();
    let bobs_private = bob_keypair.private_key_bytes();

    let bobs_public = bob_keypair.public_key_bytes();

    let alice_sign_keypair = generate::<Ed25519KeyPair>(Some(&seed_alice.from_base58().unwrap()));

    let body = r#"{"foo":"bar"}"#;
    let message = Message::new()
        .from("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
        .to(&["did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"])
        .body(body)
        .as_flat_jwe(&CryptoAlgorithm::XC20P, Some(bobs_public.to_vec()))
        .kid(&hex::encode(alice_sign_keypair.public_key_bytes()));

    let jwe_string = message
        .seal_signed(
            &alice_private,
            Some(vec![Some(bobs_public.to_vec())]),
            SignatureAlgorithm::EdDsa,
            &[
                alice_sign_keypair.private_key_bytes(),
                alice_sign_keypair.public_key_bytes(),
            ]
            .concat(),
        )
        .unwrap();

    let received = Message::receive(&jwe_string.as_str(), Some(&bobs_private), None, None);
    assert!(&received.is_ok());
    let received = received.unwrap();
    let sample_body: Value = serde_json::from_str(body).unwrap();
    let received_body: Value = serde_json::from_str(&received.get_body().unwrap()).unwrap();
    assert_eq!(sample_body.to_string(), received_body.to_string(),);
}

#[test]
fn test_keypairs() {
    let seed_alice = "6QN8DfuN9hjgHgPvLXqgzqYE3jRRGRrmJQZkd5tL8paR";
    let seed_bob = "HBTcN2MrXNRj9xF9oi8QqYyuEPv3JLLjQKuEgW9oxVKP";

    let alice_private = seed_alice.from_base58().unwrap();
    let bob_private = seed_bob.from_base58().unwrap();

    let alice_secret_key: StaticSecret =
        StaticSecret::from(array_ref!(alice_private, 0, 32).to_owned());
    let bob_secret_key: StaticSecret =
        StaticSecret::from(array_ref!(bob_private, 0, 32).to_owned());

    let alice_public = PublicKey::from(&alice_secret_key);
    let bob_public = PublicKey::from(&bob_secret_key);

    let did_key_alice =
        did_key::generate::<X25519KeyPair>(Some(&seed_alice.from_base58().unwrap()));
    let did_key_bob = generate::<X25519KeyPair>(Some(&seed_bob.from_base58().unwrap()));

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

    assert_eq!(
        bob_public.to_bytes().to_vec(),
        did_key_bob.public_key_bytes()
    );
}
