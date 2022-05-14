use didcomm_mediator::invitation::InvitationResponse;
use reqwest;

#[tokio::main]
async fn main() {
    let invitation: InvitationResponse = reqwest::get("http://localhost:8000/invitation")
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    println!("{}", serde_json::to_string_pretty(&invitation).unwrap());
}
