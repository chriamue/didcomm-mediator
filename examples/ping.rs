use did_key::{generate, DIDCore, KeyMaterial, X25519KeyPair};
use didcomm_mediator::invitation::InvitationResponse;
use didcomm_mediator::message::sign_and_encrypt_message;
use didcomm_mediator::protocols::trustping::TrustPingResponseBuilder;
use didcomm_rs::Message;
use std::time::Instant;

#[tokio::main]
async fn main() {
    let key = generate::<X25519KeyPair>(None);

    let invitation: InvitationResponse = reqwest::get("http://localhost:8000/invitation")
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let did_to = invitation
        .invitation
        .services
        .first()
        .unwrap()
        .recipient_keys
        .first()
        .unwrap();

    println!("PING {}", did_to);

    let did_doc = key.get_did_document(Default::default());
    let did_from = did_doc.id.to_string();

    let invitation = Message::new()
        .m_type("https://didcomm.org/out-of-band/1.0/invitation")
        .from(did_to)
        .thid(&invitation.invitation.id);

    let request = TrustPingResponseBuilder::new()
        .build()
        .unwrap()
        .from(&did_from);

    let request = sign_and_encrypt_message(&invitation, &request, &key);

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
