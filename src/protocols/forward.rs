// https://identity.foundation/didcomm-messaging/spec/#messages
use crate::connections::ConnectionStorage;
use crate::handler::{DidcommHandler, HandlerResponse};
use did_key::KeyPair;
use didcomm_rs::{AttachmentBuilder, AttachmentDataBuilder, Message};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub struct ForwardBuilder {
    did: Option<String>,
    message: Option<String>,
}

impl ForwardBuilder {
    pub fn new() -> Self {
        ForwardBuilder {
            did: None,
            message: None,
        }
    }

    pub fn did(&mut self, did: String) -> &mut Self {
        self.did = Some(did);
        self
    }

    pub fn message(&mut self, message: String) -> &mut Self {
        self.message = Some(message);
        self
    }

    pub fn build(&mut self) -> Result<Message, &'static str> {
        let mut message = Message::new()
            .m_type("https://didcomm.org/routing/2.0/forward")
            .body(&json!({"next": self.did.as_ref().unwrap()}).to_string());
        message.append_attachment(
            AttachmentBuilder::new(true).with_data(
                AttachmentDataBuilder::new()
                    .with_link("")
                    .with_json(self.message.as_ref().unwrap()),
            ),
        );
        Ok(message)
    }
}

#[derive(Default)]
pub struct ForwardHandler {}

impl DidcommHandler for ForwardHandler {
    fn handle(
        &self,
        request: &Message,
        _key: Option<&KeyPair>,
        _connections: Option<&Arc<Mutex<Box<dyn ConnectionStorage>>>>,
    ) -> HandlerResponse {
        if request
            .get_didcomm_header()
            .m_type
            .starts_with("https://didcomm.org/routing/2.0/forward")
        {
            match request.get_attachments().next() {
                Some(attachment) => {
                    let body: Value = serde_json::from_str(&request.get_body().unwrap()).unwrap();
                    let did_to = body["next"].as_str().unwrap();
                    let response_json = attachment.data.json.as_ref().unwrap();
                    HandlerResponse::Forward(
                        vec![did_to.to_string()],
                        serde_json::from_str(response_json).unwrap(),
                    )
                }
                _ => HandlerResponse::Processed,
            }
        } else {
            HandlerResponse::Skipped
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_forward() {
        let message = "{}".to_string();
        let response = ForwardBuilder::new()
            .did("did:test".to_string())
            .message(message)
            .build()
            .unwrap();

        assert_eq!(
            response.get_didcomm_header().m_type,
            "https://didcomm.org/routing/2.0/forward"
        );
        assert!(response.get_attachments().next().is_some());

        println!("{}", serde_json::to_string_pretty(&response).unwrap());
    }
}
