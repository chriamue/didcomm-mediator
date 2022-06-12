use reqwest;
use serde_json::Value;

#[tokio::main]
async fn main() {
    let invitation: Value = reqwest::get("http://localhost:8000/invitation")
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    println!("{}", serde_json::to_string_pretty(&invitation).unwrap());
}
