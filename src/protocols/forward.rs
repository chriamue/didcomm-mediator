// https://identity.foundation/didcomm-messaging/spec/#messages
use didcomm_rs::{AttachmentBuilder, AttachmentDataBuilder, Message};
use serde_json::json;

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
            AttachmentBuilder::new(true)
                .with_id("best attachment")
                .with_data(
                    AttachmentDataBuilder::new().with_raw_payload(self.message.as_ref().unwrap()),
                ),
        );
        Ok(message)
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
