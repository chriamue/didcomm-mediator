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
                Some("https://didcomm.org/didexchange/1.0/request") => self.build_response(),
                _ => Err("unsupported message"),
            },
            None => Err("no message"),
        }
    }

    fn build_request(&mut self) -> Result<Value, &'static str> {
        Ok(json!({
            "@id": Uuid::new_v4(),
            "~thread": {
                "pthid": self.message.clone().unwrap()["@id"].as_str().unwrap()
            },
            "@type": "https://didcomm.org/didexchange/1.0/request",
            "goal": "To create a relationship",
            "did": self.did.clone().unwrap(),
            "did_doc~attach": self.did_doc.clone().unwrap()
        }))
    }

    fn build_response(&mut self) -> Result<Value, &'static str> {
        Ok(json!({
            "@id": Uuid::new_v4(),
            "~thread": {
                "pthid": self.message.clone().unwrap()["@id"].as_str().unwrap()
            },
            "@type": "https://didcomm.org/didexchange/1.0/response",
            "did": self.did.clone().unwrap(),
            "did_doc~attach": self.did_doc.clone().unwrap()
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::invitation::Invitation;
    use did_key::{generate, DIDCore, X25519KeyPair, CONFIG_LD_PUBLIC};

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
        let keypair = generate::<X25519KeyPair>(None);
        let did_doc = serde_json::to_value(keypair.get_did_document(CONFIG_LD_PUBLIC)).unwrap();

        let response = DidExchangeResponseBuilder::new()
            .message(invitation)
            .did("did:key:z6MkpFZ86WuUpihn1mTRbpBCGE6YpCvsBYtZQYnd9jcuAUup".to_string())
            .did_doc(did_doc)
            .build()
            .unwrap();

        assert_eq!(
            response["@type"].as_str(),
            Some("https://didcomm.org/didexchange/1.0/request")
        );

        println!("{}", serde_json::to_string_pretty(&response).unwrap());
    }

    #[test]
    fn test_build_response() {
        let alice_key = generate::<X25519KeyPair>(None);
        let bob_key = generate::<X25519KeyPair>(None);
        let invitation = Invitation::new(
            "did:key:peer".to_string(),
            "Alice".to_string(),
            "".to_string(),
        );
        let did_doc = serde_json::to_value(alice_key.get_did_document(CONFIG_LD_PUBLIC)).unwrap();

        let request = DidExchangeResponseBuilder::new()
            .message(serde_json::to_value(&invitation).unwrap())
            .did("did:key:z6MkpFZ86WuUpihn1mTRbpBCGE6YpCvsBYtZQYnd9jcuAUup".to_string())
            .did_doc(did_doc)
            .build()
            .unwrap();

        assert_eq!(
            request["@type"].as_str(),
            Some("https://didcomm.org/didexchange/1.0/request")
        );

        let did_doc = serde_json::to_value(bob_key.get_did_document(CONFIG_LD_PUBLIC)).unwrap();

        let response = DidExchangeResponseBuilder::new()
            .message(request)
            .did("did:key:z6MkpFZ86WuUpihn1mTRbpBCGE6YpCvsBYtZQYnd9jcuAUup".to_string())
            .did_doc(did_doc)
            .build()
            .unwrap();

        assert_eq!(
            response["@type"].as_str(),
            Some("https://didcomm.org/didexchange/1.0/response")
        );

        println!("{}", serde_json::to_string_pretty(&response).unwrap());
    }
}
