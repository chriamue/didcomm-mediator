// https://identity.foundation/didcomm-messaging/spec/#discover-features-protocol-20

use crate::connections::ConnectionStorage;
use crate::handler::{DidcommHandler, HandlerResponse};
use crate::message::sign_and_encrypt_message;
use async_mutex::Mutex;
use async_trait::async_trait;
use did_key::KeyPair;
use didcomm_rs::Message;
use serde_json::json;
use std::error::Error;
use std::sync::Arc;

#[derive(Default)]
pub struct DiscoverFeaturesResponseBuilder {
    message: Option<Message>,
}

impl DiscoverFeaturesResponseBuilder {
    pub fn new() -> Self {
        DiscoverFeaturesResponseBuilder { message: None }
    }

    pub fn message(&mut self, message: Message) -> &mut Self {
        self.message = Some(message);
        self
    }

    pub fn build(&mut self) -> Result<Message, &'static str> {
        match &self.message {
            Some(message) => match message.get_didcomm_header().m_type.as_str() {
                "https://didcomm.org/discover-features/2.0/queries" => self.build_disclose(),
                _ => Err("unsupported message"),
            },
            None => self.build_query(),
        }
    }

    pub fn build_query(&mut self) -> Result<Message, &'static str> {
        Ok(Message::new()
            .m_type("https://didcomm.org/discover-features/2.0/queries")
            .body(
                &json!({"queries": [
                    { "feature-type": "goal-code", "match": "org.didcomm.*" }
                ]})
                .to_string(),
            ))
    }

    pub fn build_disclose(&mut self) -> Result<Message, &'static str> {
        Ok(Message::new()
            .m_type("https://didcomm.org/discover-features/1.0/disclose")
            .thid(&self.message.as_ref().unwrap().get_didcomm_header().id)
            .body(
                &json!({
                    "disclosures": [
                        {
                            "feature-type": "protocol",
                            "id": "https://didcomm.org/trust-ping/2.0"
                        },
                        {
                            "feature-type": "protocol",
                            "id": "https://didcomm.org/didexchange/1.0"
                        },
                        {
                            "feature-type": "protocol",
                            "id": "https://didcomm.org/messagepickup/1.0"
                        },
                        {
                            "feature-type": "protocol",
                            "id": "https://didcomm.org/routing/2.0/forward"
                        },
                    ]
                })
                .to_string(),
            ))
    }
}

#[derive(Default)]
pub struct DiscoverFeaturesHandler {}

#[async_trait]
impl DidcommHandler for DiscoverFeaturesHandler {
    async fn handle(
        &self,
        request: &Message,
        key: Option<&KeyPair>,
        _connections: Option<&Arc<Mutex<Box<dyn ConnectionStorage>>>>,
    ) -> Result<HandlerResponse, Box<dyn Error>> {
        if request
            .get_didcomm_header()
            .m_type
            .starts_with("https://didcomm.org/discover-features/2.0")
        {
            let response = DiscoverFeaturesResponseBuilder::new()
                .message(request.clone())
                .build()
                .unwrap();
            let response = sign_and_encrypt_message(request, &response, key.unwrap());

            Ok(HandlerResponse::Response(
                serde_json::to_value(&response.unwrap()).unwrap(),
            ))
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
    fn test_build_query() {
        let response = DiscoverFeaturesResponseBuilder::new().build().unwrap();

        assert_eq!(
            response.get_didcomm_header().m_type,
            "https://didcomm.org/discover-features/2.0/queries"
        );

        println!("{}", serde_json::to_string_pretty(&response).unwrap());
    }

    #[test]
    fn test_build_disclose() {
        let ping = DiscoverFeaturesResponseBuilder::new().build().unwrap();

        assert_eq!(
            ping.get_didcomm_header().m_type,
            "https://didcomm.org/discover-features/2.0/queries"
        );

        let response = DiscoverFeaturesResponseBuilder::new()
            .message(ping)
            .build()
            .unwrap();

        assert_eq!(
            response.get_didcomm_header().m_type,
            "https://didcomm.org/discover-features/1.0/disclose"
        );

        println!("{}", serde_json::to_string_pretty(&response).unwrap());
    }

    #[tokio::test]
    async fn test_handler() {
        let key = generate::<X25519KeyPair>(None);
        let key_from = generate::<X25519KeyPair>(None);
        let did_from = key_from.get_did_document(Default::default()).id;
        let request = DiscoverFeaturesResponseBuilder::new()
            .build()
            .unwrap()
            .from(&did_from);

        assert_eq!(
            request.get_didcomm_header().m_type,
            "https://didcomm.org/discover-features/2.0/queries"
        );
        let handler = DiscoverFeaturesHandler::default();
        let response = handler.handle(&request, Some(&key), None).await;
        assert_ne!(response.unwrap(), HandlerResponse::Skipped);
    }
}
