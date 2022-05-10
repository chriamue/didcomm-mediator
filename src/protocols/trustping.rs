// https://identity.foundation/didcomm-messaging/spec/#trust-ping-protocol-20

use serde_json::{json, Value};
use uuid::Uuid;

#[derive(Default)]
pub struct TrustPingResponseBuilder {
    did: Option<String>,
    message: Option<Value>,
}

impl TrustPingResponseBuilder {
    pub fn new() -> Self {
        TrustPingResponseBuilder{
            did: None,
            message: None
        }
    }

    pub fn did(&mut self, did: String) -> &mut Self {
        self.did = Some(did);
        self
    }

    pub fn message(&mut self, message: Value) -> &mut Self {
        self.message = Some(message);
        self
    }

    pub fn build(&mut self) -> Result<Value, &'static str> {
        match &self.message {
            Some(message) => match message["type"].as_str() {
                Some("https://didcomm.org/trust-ping/2.0/ping") => self.build_response(),
                _ => Err("unsupported message"),
            },
            None => self.build_ping(),
        }
    }

    fn build_ping(&mut self) -> Result<Value, &'static str> {
        let id = Uuid::new_v4();
        Ok(json!({
          "type": "https://didcomm.org/trust-ping/2.0/ping",
          "id": id,
          "from": self.did.clone().unwrap(),
          "body": {
              "response_requested": true
          }
        }))
    }

    fn build_response(&mut self) -> Result<Value, &'static str> {
        let id = Uuid::new_v4();
        Ok(json!({
          "type": "https://didcomm.org/trust-ping/2.0/ping-response",
          "id": id,
          "thid": self.message.clone().unwrap()["id"].as_str().unwrap()
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use did_key::{generate, DIDCore, X25519KeyPair, CONFIG_LD_PUBLIC};

    #[test]
    fn test_build_ping() {
        let response = TrustPingResponseBuilder::new()
            .did("did:key:z6MkpFZ86WuUpihn1mTRbpBCGE6YpCvsBYtZQYnd9jcuAUup".to_string())
            .build()
            .unwrap();

        assert_eq!(
            response["type"].as_str(),
            Some("https://didcomm.org/trust-ping/2.0/ping")
        );

        println!("{}", serde_json::to_string_pretty(&response).unwrap());
    }

    #[test]
    fn test_build_response() {
        let ping = TrustPingResponseBuilder::new()
            .did("did:key:z6MkpFZ86WuUpihn1mTRbpBCGE6YpCvsBYtZQYnd9jcuAUup".to_string())
            .build()
            .unwrap();

        assert_eq!(
            ping["type"].as_str(),
            Some("https://didcomm.org/trust-ping/2.0/ping")
        );

        let response = TrustPingResponseBuilder::new()
            .message(ping)
            .did("did:key:z6MkpFZ86WuUpihn1mTRbpBCGE6YpCvsBYtZQYnd9jcuAUup".to_string())
            .build()
            .unwrap();

        assert_eq!(
            response["type"].as_str(),
            Some("https://didcomm.org/trust-ping/2.0/ping-response")
        );

        println!("{}", serde_json::to_string_pretty(&response).unwrap());
    }
}
