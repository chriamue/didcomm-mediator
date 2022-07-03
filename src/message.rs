use crate::resolver::resolve;
use did_key::{generate, DIDCore, Ed25519KeyPair, KeyMaterial, KeyPair};
use didcomm_rs::Jwe;
use didcomm_rs::{
    crypto::{CryptoAlgorithm, SignatureAlgorithm},
    Message,
};
use serde_json::{json, Value};

pub async fn sign_and_encrypt_message(
    request: &Message,
    response: &Message,
    key: &KeyPair,
) -> Result<Value, Box<dyn std::error::Error>> {
    let recipient_did = request.get_didcomm_header().from.as_ref().unwrap();
    let encrypted = sign_and_encrypt(
        response,
        &key.get_did_document(Default::default()).id,
        recipient_did,
        key,
    )
    .await
    .unwrap();
    Ok(encrypted)
}

pub async fn sign_and_encrypt(
    message: &Message,
    did_from: &str,
    did_to: &str,
    key: &KeyPair,
) -> Result<Value, Box<dyn std::error::Error>> {
    let sign_key = generate::<Ed25519KeyPair>(None);

    let recipient_public_key = resolve(did_to).await.unwrap();

    let response = message
        .clone()
        .from(did_from)
        .to(&[did_to])
        .as_jwe(&CryptoAlgorithm::XC20P, Some(recipient_public_key.to_vec()))
        .kid(&hex::encode(sign_key.public_key_bytes()));

    let ready_to_send = response
        .seal_signed(
            &key.private_key_bytes(),
            Some(vec![Some(recipient_public_key)]),
            SignatureAlgorithm::EdDsa,
            &[sign_key.private_key_bytes(), sign_key.public_key_bytes()].concat(),
        )
        .unwrap();
    Ok(serde_json::from_str(&ready_to_send).unwrap())
}

pub fn add_return_route_all_header(message: Message) -> Message {
    message.add_header_field(
        "~transport".to_string(),
        serde_json::to_string(&json!({
            "return_route": "all".to_string()
        }))
        .unwrap(),
    )
}

pub fn has_return_route_all_header(message: &Message) -> bool {
    match message
        .get_application_params()
        .find(|(key, _)| *key == "~transport")
    {
        Some((_, transport)) => {
            serde_json::from_str::<Value>(transport).unwrap()
                == json!({
                    "return_route": "all".to_string()
                })
        }
        _ => false,
    }
}

pub async fn receive(
    incoming: &str,
    encryption_recipient_private_key: Option<&[u8]>,
    encryption_sender_public_key: Option<Vec<u8>>,
    signing_sender_public_key: Option<&[u8]>,
) -> Result<Message, didcomm_rs::Error> {
    let sender_public_key = match &encryption_sender_public_key {
        Some(value) => value.to_vec(),
        None => {
            let jwe: Jwe = serde_json::from_str(incoming)?;
            let skid = &jwe
                .get_skid()
                .ok_or_else(|| didcomm_rs::Error::Generic("skid missing".to_string()))?;
            resolve(skid).await.unwrap()
        }
    };
    Message::receive(
        incoming,
        encryption_recipient_private_key,
        Some(sender_public_key),
        signing_sender_public_key,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use base58::FromBase58;
    use did_key::X25519KeyPair;

    #[tokio::test]
    async fn test_encrypt_message() {
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

        let jwe_string = serde_json::to_string(
            &sign_and_encrypt_message(&request, &message, &alice_keypair)
                .await
                .unwrap(),
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
    fn test_return_route_all() {
        let mut message = Message::new();
        assert!(!has_return_route_all_header(&message));
        message = add_return_route_all_header(message);
        assert!(has_return_route_all_header(&message));
    }

    #[cfg(feature = "iota")]
    #[tokio::test]
    async fn test_iota_message_encryption() -> Result<(), Box<dyn std::error::Error>> {
        use crate::config::Config;
        use identity_iota::prelude::KeyPair;
        use identity_iota::prelude::*;
        use rocket;

        let rocket = rocket::build();
        let figment = rocket.figment();
        let config: Config = figment.extract().expect("config");

        let seed = config.key_seed.unwrap();
        let private = seed.from_base58().unwrap();

        let keypair = generate::<X25519KeyPair>(Some(&private));
        let receiver_keypair_ex =
            KeyPair::try_from_private_key_bytes(KeyType::X25519, &private).unwrap();

        let did_from = config.did_iota.as_ref().unwrap().to_string();
        let did_to = config.did_iota.unwrap();

        let message = Message::new();
        let message = serde_json::to_string(
            &sign_and_encrypt(&message, &did_from, &did_to, &keypair)
                .await
                .unwrap(),
        )
        .unwrap();

        println!("{:?}", message);

        let received = receive(
            &message,
            Some(&receiver_keypair_ex.private().as_ref()),
            None,
            None,
        )
        .await;
        received.unwrap();

        Ok(())
    }
}
