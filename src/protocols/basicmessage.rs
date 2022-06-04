// https://didcomm.org/basicmessage/2.0/

use crate::connections::ConnectionStorage;
use crate::handler::{DidcommHandler, HandlerResponse};
use async_mutex::Mutex;
use async_trait::async_trait;
use did_key::KeyPair;
use didcomm_rs::Message;
use serde_json::json;
use std::error::Error;
use std::sync::Arc;

#[derive(Default)]
pub struct BasicMessageBuilder {
    message: Option<String>,
    lang: Option<String>,
}

impl BasicMessageBuilder {
    pub fn new() -> Self {
        BasicMessageBuilder {
            message: None,
            lang: Some("en".to_string()),
        }
    }

    pub fn message(&mut self, message: String) -> &mut Self {
        self.message = Some(message);
        self
    }

    pub fn lang(&mut self, lang: String) -> &mut Self {
        self.lang = Some(lang);
        self
    }

    pub fn build(&mut self) -> Result<Message, &'static str> {
        Ok(Message::new()
            .m_type("https://didcomm.org/basicmessage/2.0/message")
            .body(&json!({"content": self.message.as_ref().unwrap()}).to_string()))
    }
}

#[derive(Default)]
pub struct BasicMessageHandler {}

#[async_trait]
impl DidcommHandler for BasicMessageHandler {
    async fn handle(
        &self,
        request: &Message,
        _key: Option<&KeyPair>,
        _connections: Option<&Arc<Mutex<Box<dyn ConnectionStorage>>>>,
    ) -> Result<HandlerResponse, Box<dyn Error>> {
        if request
            .get_didcomm_header()
            .m_type
            .starts_with("https://didcomm.org/basicmessage/2.0/message")
        {
            Ok(HandlerResponse::Processed)
        } else {
            Ok(HandlerResponse::Skipped)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use did_key::{generate, DIDCore, X25519KeyPair};

    #[test]
    fn test_build_message() {
        let message = "Hello World".to_string();
        let response = BasicMessageBuilder::new()
            .message(message.to_string())
            .build()
            .unwrap();

        assert_eq!(
            response.get_didcomm_header().m_type,
            "https://didcomm.org/basicmessage/2.0/message"
        );
        assert_eq!(
            response.get_body().unwrap(),
            serde_json::to_string(&json!({ "content": message })).unwrap()
        );
        println!("{}", serde_json::to_string_pretty(&response).unwrap());
    }

    #[tokio::test]
    async fn test_handler() {
        let key = generate::<X25519KeyPair>(None);
        let message = BasicMessageBuilder::new()
            .message("Hello World!".to_string())
            .build()
            .unwrap();
        let message = message.from(&key.get_did_document(Default::default()).id);

        assert_eq!(
            message.get_didcomm_header().m_type,
            "https://didcomm.org/basicmessage/2.0/message"
        );
        let handler = BasicMessageHandler::default();
        let response = handler.handle(&message, Some(&key), None).await;
        assert_ne!(response.unwrap(), HandlerResponse::Skipped);
    }
}
