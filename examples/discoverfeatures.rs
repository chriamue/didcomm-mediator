use did_key::{generate, DIDCore, KeyMaterial, X25519KeyPair};
use didcomm_mediator::invitation::InvitationResponse;
use didcomm_mediator::message::sign_and_encrypt;
use didcomm_mediator::protocols::discoverfeatures::DiscoverFeaturesResponseBuilder;
use didcomm_rs::Message;

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

    let request = DiscoverFeaturesResponseBuilder::new().build().unwrap();

    let request = sign_and_encrypt(
        &request,
        &key.get_did_document(Default::default()).id,
        did_to,
        &key,
    )
    .await
    .unwrap();

    let client = reqwest::Client::new();
    let res = client
        .post("http://localhost:8000/didcomm")
        .json(&request)
        .send()
        .await
        .unwrap();

    let body = res.text().await.unwrap();

    let received = Message::receive(&body, Some(&key.private_key_bytes()), None, None).unwrap();

    println!("{}", serde_json::to_string_pretty(&received).unwrap());
}
