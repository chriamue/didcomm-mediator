use did_key::{generate, DIDCore, KeyMaterial, X25519KeyPair};
use didcomm_mediator::message::sign_and_encrypt_message;
use didcomm_mediator::protocols::trustping::TrustPingResponseBuilder;
use didcomm_mediator::service::Service;
use didcomm_rs::Message;
use std::time::Instant;

#[tokio::main]
async fn main() {
    let key = generate::<X25519KeyPair>(None);

    let invitation: Message = reqwest::get("http://localhost:8000/invitation")
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let (_, services) = invitation
        .get_application_params()
        .find(|(key, _)| *key == "services")
        .unwrap();
    let services: Vec<Service> = serde_json::from_str(services).unwrap();

    let did_to = services.first().unwrap().id.replace("#didcomm", "");

    println!("PING {}", did_to);

    let did_doc = key.get_did_document(Default::default());
    let did_from = did_doc.id.to_string();

    let request = TrustPingResponseBuilder::new()
        .build()
        .unwrap()
        .from(&did_from);

    let request = sign_and_encrypt_message(&invitation, &request, &key)
        .await
        .unwrap();

    let start = Instant::now();

    let client = reqwest::Client::new();
    let res = client
        .post("http://localhost:8000/didcomm")
        .json(&request)
        .send()
        .await
        .unwrap();

    let body = res.text().await.unwrap();

    let received = Message::receive(&body, Some(&key.private_key_bytes()), None, None).unwrap();

    let duration = start.elapsed();

    println!("time = {:?}", duration);

    println!("{}", serde_json::to_string_pretty(&received).unwrap());
}
