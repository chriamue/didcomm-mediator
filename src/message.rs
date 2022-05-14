use did_key::{generate, DIDCore, Ed25519KeyPair, KeyMaterial, KeyPair};
use didcomm_rs::{
    crypto::{CryptoAlgorithm, SignatureAlgorithm},
    Message,
};
use serde_json::Value;

pub fn sign_and_encrypt_message(request: &Message, response: &Message, key: &KeyPair) -> Value {
    let sign_key = generate::<Ed25519KeyPair>(None);

    let sender_did = key.get_did_document(Default::default()).id;
    let recipient_did = request.get_didcomm_header().from.as_ref().unwrap();
    let recipient_key = did_key::resolve(recipient_did).unwrap();

    let response = response
        .clone()
        .from(&sender_did)
        .to(&[recipient_did])
        .as_jwe(
            &CryptoAlgorithm::XC20P,
            Some(recipient_key.public_key_bytes()),
        )
        .kid(&hex::encode(sign_key.public_key_bytes()));

    println!("{:?}", response);

    let ready_to_send = response
        .seal_signed(
            &key.private_key_bytes(),
            Some(vec![Some(recipient_key.public_key_bytes())]),
            SignatureAlgorithm::EdDsa,
            &[sign_key.private_key_bytes(), sign_key.public_key_bytes()].concat(),
        )
        .unwrap();
    serde_json::from_str(&ready_to_send).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base58::FromBase58;
    use did_key::X25519KeyPair;

    #[test]
    fn test_encrypt_message() {
        let seed_alice = "6QN8DfuN9hjgHgPvLXqgzqYE3jRRGRrmJQZkd5tL8paR";
        let seed_bob = "HBTcN2MrXNRj9xF9oi8QqYyuEPv3JLLjQKuEgW9oxVKP";

        let alice_keypair = generate::<X25519KeyPair>(Some(&seed_alice.from_base58().unwrap()));
        let bob_keypair = generate::<X25519KeyPair>(Some(&seed_bob.from_base58().unwrap()));
        let bobs_private = bob_keypair.private_key_bytes();

        let request = Message::new()
            .from("did:key:z6LSrHyXiPBhUbvPUtyUCdf32sniiMGPTAesgHrtEa4FePtr")
            .to(&["did:key:z6LShs9GGnqk85isEBzzshkuVWrVKsRp24GnDuHk8QWkARMW"]);

        let body = r#"{"foo":"bar"}"#;
        let message = Message::new().body(body);

        let jwe_string = serde_json::to_string(&sign_and_encrypt_message(
            &request,
            &message,
            &alice_keypair,
        ))
        .unwrap();

        let received = Message::receive(&jwe_string.as_str(), Some(&bobs_private), None, None);

        assert!(&received.is_ok());
        let received = received.unwrap();
        let sample_body: Value = serde_json::from_str(body).unwrap();
        let received_body: Value = serde_json::from_str(&received.get_body().unwrap()).unwrap();
        assert_eq!(sample_body.to_string(), received_body.to_string(),);
    }
}
