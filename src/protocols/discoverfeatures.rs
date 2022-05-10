// https://identity.foundation/didcomm-messaging/spec/#discover-features-protocol-20

use serde_json::{json, Value};
use uuid::Uuid;

#[derive(Default)]
pub struct DiscoverFeaturesResponseBuilder {
    message: Option<Value>,
}

impl DiscoverFeaturesResponseBuilder {
    pub fn new() -> Self {
        DiscoverFeaturesResponseBuilder { message: None }
    }

    pub fn message(&mut self, message: Value) -> &mut Self {
        self.message = Some(message);
        self
    }

    pub fn build(&mut self) -> Result<Value, &'static str> {
        match &self.message {
            Some(message) => match message["type"].as_str() {
                Some("https://didcomm.org/discover-features/2.0/queries") => self.build_disclose(),
                _ => Err("unsupported message"),
            },
            None => self.build_query(),
        }
    }

    fn build_query(&mut self) -> Result<Value, &'static str> {
        let id = Uuid::new_v4();
        Ok(json!({
            "type": "https://didcomm.org/discover-features/2.0/queries",
            "id": id,
            "body": {
                "queries": [
                    { "feature-type": "protocol", "match": "https://didcomm.org/tictactoe/1.*" },
                    { "feature-type": "goal-code", "match": "org.didcomm.*" }
                ]
            }
        }))
    }

    fn build_disclose(&mut self) -> Result<Value, &'static str> {
        let id = Uuid::new_v4();
        Ok(json!({
            "type": "https://didcomm.org/discover-features/1.0/disclose",
            "thid": self.message.clone().unwrap()["id"].as_str().unwrap(),
            "body":{
                "disclosures": [
                    {
                        "feature-type": "protocol",
                        "id": "https://didcomm.org/trust-ping"
                    },
                ]
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_query() {
        let response = DiscoverFeaturesResponseBuilder::new().build().unwrap();

        assert_eq!(
            response["type"].as_str(),
            Some("https://didcomm.org/discover-features/2.0/queries")
        );

        println!("{}", serde_json::to_string_pretty(&response).unwrap());
    }

    #[test]
    fn test_build_disclose() {
        let ping = DiscoverFeaturesResponseBuilder::new().build().unwrap();

        assert_eq!(
            ping["type"].as_str(),
            Some("https://didcomm.org/discover-features/2.0/queries")
        );

        let response = DiscoverFeaturesResponseBuilder::new()
            .message(ping)
            .build()
            .unwrap();

        assert_eq!(
            response["type"].as_str(),
            Some("https://didcomm.org/discover-features/1.0/disclose")
        );

        println!("{}", serde_json::to_string_pretty(&response).unwrap());
    }
}
