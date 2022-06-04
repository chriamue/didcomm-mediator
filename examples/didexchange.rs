use did_key::{generate, DIDCore, KeyMaterial, X25519KeyPair, CONFIG_LD_PUBLIC};
use didcomm_mediator::invitation::InvitationResponse;
use didcomm_mediator::message::sign_and_encrypt;
use didcomm_mediator::protocols::didexchange::DidExchangeResponseBuilder;
use didcomm_rs::Message;

#[tokio::main]
async fn main() {
    let key = generate::<X25519KeyPair>(None);
    let did_doc = key.get_did_document(CONFIG_LD_PUBLIC);
    let did_from = did_doc.id.to_string();

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

    let invitation = Message::new()
        .m_type("https://didcomm.org/out-of-band/1.0/invitation")
        .thid(&invitation.invitation.id);

    let request = DidExchangeResponseBuilder::new()
        .message(invitation)
        .did(did_from.to_string())
        .did_doc(serde_json::to_value(did_doc).unwrap())
        .build()
        .unwrap();

    let request = sign_and_encrypt(&request, did_to, &key).unwrap();

    let client = reqwest::Client::new();
    let res = client
        .post("http://localhost:8000/didcomm")
        .json(&request)
        .send()
        .await
        .unwrap();

    let body = res.text().await.unwrap();

    let response = Message::receive(&body, Some(&key.private_key_bytes()), None, None).unwrap();
    let complete = DidExchangeResponseBuilder::new()
        .message(response)
        .build()
        .unwrap();

    let res = client
        .post("http://localhost:8000/didcomm")
        .json(&complete)
        .send()
        .await
        .unwrap();

    let body = res.text().await.unwrap();
    println!(
        "did exchange completed: {}",
        serde_json::to_string_pretty(&body).unwrap()
    );
}
