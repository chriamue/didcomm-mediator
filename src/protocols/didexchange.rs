use serde_json::{json, Value};
use uuid::Uuid;

#[derive(Default)]
pub struct DidExchangeResponseBuilder {
    did: Option<String>,
    message: Option<Value>,
    did_doc: Option<Value>,
}

impl DidExchangeResponseBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn did(&mut self, did: String) -> &mut Self {
        self.did = Some(did);
        self
    }

    pub fn message(&mut self, message: Value) -> &mut Self {
        self.message = Some(message);
        self
    }

    pub fn did_doc(&mut self, did_doc: Value) -> &mut Self {
        self.did_doc = Some(did_doc);
        self
    }

    pub fn build(&mut self) -> Result<Value, &'static str> {
        match &self.message {
            Some(message) => match message["@type"].as_str() {
                Some("https://didcomm.org/out-of-band/1.0/invitation") => self.build_request(),
                _ => Err("unsupported message"),
            },
            None => Err("no message"),
        }
    }

    fn build_request(&mut self) -> Result<Value, &'static str> {
        Ok(json!({
            "@id": Uuid::new_v4(),
            "@type": "https://didcomm.org/didexchange/1.0/request",
            "goal": "To create a relationship",
            "did": self.did.clone().unwrap()
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_resquest() {
        let invitation = r#"
        {
            "@id": "949034e0-f1e3-4067-bf2e-ce1ff7a831d4",
            "@type": "https://didcomm.org/out-of-band/1.0/invitation",
            "accept": [
              "didcomm/v2"
            ],
            "handshake_protocols": [
              "https://didcomm.org/didexchange/1.0"
            ],
            "label": "did-planning-poker",
            "services": [
              {
                "id": "2e9e814a-c1e1-416e-a21a-a4182809950c",
                "recipientKeys": [
                  "did:key:z6MkpFZ86WuUpihn1mTRbpBCGE6YpCvsBYtZQYnd9jcuAUup"
                ],
                "serviceEndpoint": "ws://localhost:8082",
                "type": "did-communication"
              }
            ]
          }
        "#;
        let invitation = serde_json::from_str(invitation).unwrap();
        let response = DidExchangeResponseBuilder::new()
            .message(invitation)
            .did("did:key:z6MkpFZ86WuUpihn1mTRbpBCGE6YpCvsBYtZQYnd9jcuAUup".to_string())
            .build()
            .unwrap();

        assert_eq!(
            response["@type"].as_str(),
            Some("https://didcomm.org/didexchange/1.0/request")
        );

        println!("{}", serde_json::to_string_pretty(&response).unwrap());
    }
}
