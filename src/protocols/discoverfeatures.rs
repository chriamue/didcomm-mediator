// https://identity.foundation/didcomm-messaging/spec/#discover-features-protocol-20

use crate::connections::Connections;
use crate::handler::{DidcommHandler, HandlerResponse};
use did_key::KeyPair;
use didcomm_rs::Message;
use serde_json::json;

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

    fn build_query(&mut self) -> Result<Message, &'static str> {
        Ok(Message::new()
            .m_type("https://didcomm.org/discover-features/2.0/queries")
            .body(
                &json!({"queries": [
                    { "feature-type": "protocol", "match": "https://didcomm.org/tictactoe/1.*" },
                    { "feature-type": "goal-code", "match": "org.didcomm.*" }
                ]})
                .to_string(),
            ))
    }

    fn build_disclose(&mut self) -> Result<Message, &'static str> {
        Ok(Message::new()
            .m_type("https://didcomm.org/discover-features/1.0/disclose")
            .thid(&self.message.as_ref().unwrap().get_didcomm_header().id)
            .body(
                &json!({
                    "disclosures": [
                        {
                            "feature-type": "protocol",
                            "id": "https://didcomm.org/trust-ping"
                        },
                    ]
                })
                .to_string(),
            ))
    }
}

#[derive(Default)]
pub struct DiscoverFeaturesHandler {}

impl DidcommHandler for DiscoverFeaturesHandler {
    fn handle(
        &self,
        request: &Message,
        _key: Option<&KeyPair>,
        _connections: Option<&Connections>,
    ) -> HandlerResponse {
        if request
            .get_didcomm_header()
            .m_type
            .starts_with("https://didcomm.org/discover-features/2.0")
        {
            let response = DiscoverFeaturesResponseBuilder::new()
                .message(request.clone())
                .build()
                .unwrap();
            HandlerResponse::Response(serde_json::to_value(&response).unwrap())
        } else {
            HandlerResponse::Skipped
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_handler() {
        let ping = DiscoverFeaturesResponseBuilder::new().build().unwrap();

        assert_eq!(
            ping.get_didcomm_header().m_type,
            "https://didcomm.org/discover-features/2.0/queries"
        );
        let handler = DiscoverFeaturesHandler::default();
        let response = handler.handle(&ping, None, None);
        assert_ne!(response, HandlerResponse::Skipped);
    }
}
