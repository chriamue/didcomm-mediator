// https://identity.foundation/didcomm-messaging/spec/#trust-ping-protocol-20
use crate::connections::Connections;
use crate::handler::{DidcommHandler, HandlerResponse};
use did_key::KeyPair;
use didcomm_rs::Message;
use serde_json::json;
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub struct TrustPingResponseBuilder {
    message: Option<Message>,
}

impl TrustPingResponseBuilder {
    pub fn new() -> Self {
        TrustPingResponseBuilder { message: None }
    }

    pub fn message(&mut self, message: Message) -> &mut Self {
        self.message = Some(message);
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
            .thid(&self.message.as_ref().unwrap().get_didcomm_header().id))
    }
}

#[derive(Default)]
pub struct TrustPingHandler {}

impl DidcommHandler for TrustPingHandler {
    fn handle(
        &self,
        request: &Message,
        _key: Option<&KeyPair>,
        _connections: Option<&Arc<Mutex<Connections>>>,
    ) -> HandlerResponse {
        if request
            .get_didcomm_header()
            .m_type
            .starts_with("https://didcomm.org/trust-ping/2.0/")
        {
            let response = TrustPingResponseBuilder::new()
                .message(request.clone())
                .build()
                .unwrap()
                .to(&[request.get_didcomm_header().from.as_ref().unwrap()]);
            HandlerResponse::Send(Box::new(response))
        } else {
            HandlerResponse::Skipped
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

        println!("{}", serde_json::to_string_pretty(&response).unwrap());
    }

    #[test]
    fn test_handler() {
        let key = generate::<X25519KeyPair>(None);
        let ping = TrustPingResponseBuilder::new().build().unwrap();
        let ping = ping.from(&key.get_did_document(Default::default()).id);

        assert_eq!(
            ping.get_didcomm_header().m_type,
            "https://didcomm.org/trust-ping/2.0/ping"
        );
        let handler = TrustPingHandler::default();
        let response = handler.handle(&ping, Some(&key), None);
        assert_ne!(response, HandlerResponse::Skipped);
    }
}
