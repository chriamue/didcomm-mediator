// https://identity.foundation/didcomm-messaging/spec/#trust-ping-protocol-20
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
pub struct TrustPingResponseBuilder {
    thid: Option<String>,
    message: Option<Message>,
}

impl TrustPingResponseBuilder {
    pub fn new() -> Self {
        TrustPingResponseBuilder {
            thid: None,
            message: None,
        }
    }

    pub fn message(&mut self, message: Message) -> &mut Self {
        self.message = Some(message);
        self
    }

    pub fn thid(&mut self, thid: String) -> &mut Self {
        self.thid = Some(thid);
        self
    }

    pub fn build(&mut self) -> Result<Message, &'static str> {
        match &self.message {
            Some(message) => match message.get_didcomm_header().m_type.as_str() {
                "https://didcomm.org/trust-ping/2.0/ping" => self.build_response(),
                _ => Err("unsupported message"),
            },
            None => self.build_ping(),
        }
    }

    pub fn build_ping(&mut self) -> Result<Message, &'static str> {
        Ok(Message::new()
            .m_type("https://didcomm.org/trust-ping/2.0/ping")
            .body(&json!({"response_requested": true}).to_string()))
    }

    pub fn build_response(&mut self) -> Result<Message, &'static str> {
        Ok(Message::new()
            .m_type("https://didcomm.org/trust-ping/2.0/ping-response")
            .thid(
                self.thid
                    .as_ref()
                    .unwrap_or_else(|| &self.message.as_ref().unwrap().get_didcomm_header().id),
            ))
    }
}

#[derive(Default)]
pub struct TrustPingHandler {}

#[async_trait]
impl DidcommHandler for TrustPingHandler {
    async fn handle(
        &self,
        request: &Message,
        _key: Option<&KeyPair>,
        _connections: Option<&Arc<Mutex<Box<dyn ConnectionStorage>>>>,
    ) -> Result<HandlerResponse, Box<dyn Error>> {
        if request
            .get_didcomm_header()
            .m_type
            .starts_with("https://didcomm.org/trust-ping/2.0/")
        {
            let did_to = request.get_didcomm_header().from.clone().unwrap();
            let response = TrustPingResponseBuilder::new()
                .message(request.clone())
                .build()
                .unwrap();
            Ok(HandlerResponse::Send(did_to, Box::new(response)))
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
    fn test_build_ping() {
        let response = TrustPingResponseBuilder::new().build().unwrap();

        assert_eq!(
            response.get_didcomm_header().m_type,
            "https://didcomm.org/trust-ping/2.0/ping"
        );

        println!("{}", serde_json::to_string_pretty(&response).unwrap());
    }

    #[test]
    fn test_build_response() {
        let ping = TrustPingResponseBuilder::new().build().unwrap();

        assert_eq!(
            ping.get_didcomm_header().m_type,
            "https://didcomm.org/trust-ping/2.0/ping"
        );

        let response = TrustPingResponseBuilder::new()
            .message(ping)
            .build()
            .unwrap();

        assert_eq!(
            response.get_didcomm_header().m_type,
            "https://didcomm.org/trust-ping/2.0/ping-response"
        );

        let response = TrustPingResponseBuilder::new()
            .thid("42".to_string())
            .build_response()
            .unwrap();

        assert_eq!(
            response.get_didcomm_header().m_type,
            "https://didcomm.org/trust-ping/2.0/ping-response"
        );

        println!("{}", serde_json::to_string_pretty(&response).unwrap());
    }

    #[tokio::test]
    async fn test_handler() {
        let key = generate::<X25519KeyPair>(None);
        let ping = TrustPingResponseBuilder::new().build().unwrap();
        let ping = ping.from(&key.get_did_document(Default::default()).id);

        assert_eq!(
            ping.get_didcomm_header().m_type,
            "https://didcomm.org/trust-ping/2.0/ping"
        );
        let handler = TrustPingHandler::default();
        let response = handler.handle(&ping, Some(&key), None).await;
        assert_ne!(response.unwrap(), HandlerResponse::Skipped);
    }
}
