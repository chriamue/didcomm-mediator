// https://identity.foundation/didcomm-messaging/spec/#trust-ping-protocol-20
use didcomm_rs::Message;
use serde_json::json;
use uuid::Uuid;

#[derive(Default)]
pub struct TrustPingResponseBuilder {
    did: Option<String>,
    message: Option<Message>,
}

impl TrustPingResponseBuilder {
    pub fn new() -> Self {
        TrustPingResponseBuilder {
            did: None,
            message: None,
        }
    }

    pub fn did(&mut self, did: String) -> &mut Self {
        self.did = Some(did);
        self
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

    fn build_ping(&mut self) -> Result<Message, &'static str> {
        let id = Uuid::new_v4();
        Ok(Message::new()
            .m_type("https://didcomm.org/trust-ping/2.0/ping")
            .add_header_field("id".to_string(), id.to_string())
            .body(&json!({"response_requested": true}).to_string()))
    }

    fn build_response(&mut self) -> Result<Message, &'static str> {
        let id = Uuid::new_v4();
        Ok(Message::new()
            .m_type("https://didcomm.org/trust-ping/2.0/ping-response")
            .add_header_field("id".to_string(), id.to_string())
            .thid(&self.message.as_ref().unwrap().get_didcomm_header().id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_ping() {
        let response = TrustPingResponseBuilder::new()
            .did("did:key:z6MkpFZ86WuUpihn1mTRbpBCGE6YpCvsBYtZQYnd9jcuAUup".to_string())
            .build()
            .unwrap();

        assert_eq!(
            response.get_didcomm_header().m_type,
            "https://didcomm.org/trust-ping/2.0/ping"
        );

        println!("{}", serde_json::to_string_pretty(&response).unwrap());
    }

    #[test]
    fn test_build_response() {
        let ping = TrustPingResponseBuilder::new()
            .did("did:key:z6MkpFZ86WuUpihn1mTRbpBCGE6YpCvsBYtZQYnd9jcuAUup".to_string())
            .build()
            .unwrap();

        assert_eq!(
            ping.get_didcomm_header().m_type,
            "https://didcomm.org/trust-ping/2.0/ping"
        );

        let response = TrustPingResponseBuilder::new()
            .message(ping)
            .did("did:key:z6MkpFZ86WuUpihn1mTRbpBCGE6YpCvsBYtZQYnd9jcuAUup".to_string())
            .build()
            .unwrap();

        assert_eq!(
            response.get_didcomm_header().m_type,
            "https://didcomm.org/trust-ping/2.0/ping-response"
        );

        println!("{}", serde_json::to_string_pretty(&response).unwrap());
    }
}
