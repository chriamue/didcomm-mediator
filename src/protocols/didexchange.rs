// https://github.com/hyperledger/aries-rfcs/blob/main/features/0023-did-exchange/README.md
use crate::connections::ConnectionStorage;
use crate::handler::{DidcommHandler, HandlerResponse};
use async_mutex::Mutex;
use async_trait::async_trait;
use did_key::KeyPair;
use did_key::{DIDCore, CONFIG_LD_PUBLIC};
use didcomm_rs::Message;
use serde_json::Value;
use std::error::Error;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Default)]
pub struct DidExchangeResponseBuilder {
    did: Option<String>,
    message: Option<Message>,
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

    pub fn message(&mut self, message: Message) -> &mut Self {
        self.message = Some(message);
        self
    }

    pub fn did_doc(&mut self, did_doc: Value) -> &mut Self {
        self.did_doc = Some(did_doc);
        self
    }

    pub fn build(&mut self) -> Result<Message, &'static str> {
        match &self.message {
            Some(message) => match message.get_didcomm_header().m_type.as_str() {
                "\"https://didcomm.org/out-of-band/2.0/invitation\"" => self.build_request(),
                "https://didcomm.org/out-of-band/2.0/invitation" => self.build_request(),
                "https://didcomm.org/didexchange/1.0/request" => self.build_response(),
                "https://didcomm.org/didexchange/1.0/response" => self.build_complete(),
                _ => {
                    println!("{}", message.get_didcomm_header().m_type.as_str());
                    Err("unsupported message")
                }
            },
            None => Err("no message"),
        }
    }

    pub fn build_request(&mut self) -> Result<Message, &'static str> {
        let thid = match &self.message {
            Some(message) => message.get_didcomm_header().thid.clone().unwrap(),
            _ => Uuid::new_v4().to_string(),
        };
        Ok(Message::new()
            .m_type("https://didcomm.org/didexchange/1.0/request")
            .thid(&thid)
            .pthid(&thid)
            .add_header_field("goal".to_string(), "To create a relationship".to_string())
            .add_header_field("did".to_string(), self.did.clone().unwrap())
            .add_header_field(
                "did_doc~attach".to_string(),
                serde_json::to_string_pretty(&self.did_doc.clone().unwrap()).unwrap(),
            ))
    }

    pub fn build_response(&mut self) -> Result<Message, &'static str> {
        Ok(Message::new()
            .m_type("https://didcomm.org/didexchange/1.0/response")
            .thid(&self.message.as_ref().unwrap().get_didcomm_header().id)
            .pthid(&self.message.as_ref().unwrap().get_didcomm_header().id)
            .add_header_field("did".to_string(), self.did.as_ref().unwrap().to_string())
            .add_header_field(
                "did_doc~attach".to_string(),
                serde_json::to_string_pretty(&self.did_doc.clone().unwrap()).unwrap(),
            ))
    }

    pub fn build_complete(&mut self) -> Result<Message, &'static str> {
        Ok(Message::new()
            .m_type("https://didcomm.org/didexchange/1.0/complete")
            .thid(
                self.message
                    .as_ref()
                    .unwrap()
                    .get_didcomm_header()
                    .thid
                    .as_ref()
                    .unwrap()
                    .as_str(),
            )
            .pthid(&self.message.as_ref().unwrap().get_didcomm_header().id))
    }
}

#[derive(Default)]
pub struct DidExchangeHandler {}

#[async_trait]
impl DidcommHandler for DidExchangeHandler {
    async fn handle(
        &self,
        request: &Message,
        key: Option<&KeyPair>,
        _connections: Option<&Arc<Mutex<Box<dyn ConnectionStorage>>>>,
    ) -> Result<HandlerResponse, Box<dyn Error>> {
        if request
            .get_didcomm_header()
            .m_type
            .eq("https://didcomm.org/didexchange/1.0/complete")
        {
            Ok(HandlerResponse::Processed)
        } else if request
            .get_didcomm_header()
            .m_type
            .starts_with("https://didcomm.org/didexchange/1.0")
        {
            let did = key.unwrap().get_did_document(CONFIG_LD_PUBLIC).id;
            let mut did_doc = key.unwrap().get_did_document(CONFIG_LD_PUBLIC);
            did_doc.verification_method[0].private_key = None;
            let did_to = request.get_didcomm_header().from.clone().unwrap();
            let response = DidExchangeResponseBuilder::new()
                .message(request.clone())
                .did(did)
                .did_doc(serde_json::to_value(&did_doc).unwrap())
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
    use crate::protocols::invitation::InvitationBuilder;
    use did_key::{generate, DIDCore, X25519KeyPair, CONFIG_LD_PUBLIC};

    #[test]
    fn test_build_resquest() {
        let keypair = generate::<X25519KeyPair>(None);
        let did_doc = serde_json::to_value(keypair.get_did_document(CONFIG_LD_PUBLIC)).unwrap();

        let invitation = Message::new()
            .m_type("https://didcomm.org/out-of-band/2.0/invitation")
            .thid(&Uuid::new_v4().to_string());
        let response = DidExchangeResponseBuilder::new()
            .message(invitation)
            .did("did:key:z6MkpFZ86WuUpihn1mTRbpBCGE6YpCvsBYtZQYnd9jcuAUup".to_string())
            .did_doc(did_doc)
            .build()
            .unwrap();

        assert_eq!(
            response.get_didcomm_header().m_type,
            "https://didcomm.org/didexchange/1.0/request"
        );

        println!("{}", serde_json::to_string_pretty(&response).unwrap());
    }

    #[test]
    fn test_build_response() {
        let alice_key = generate::<X25519KeyPair>(None);
        let bob_key = generate::<X25519KeyPair>(None);

        let invitation = InvitationBuilder::new()
            .goal("to create a relationship".to_string())
            .goal_code("aries.rel.build".to_string())
            .build()
            .unwrap();

        let did_doc = serde_json::to_value(alice_key.get_did_document(CONFIG_LD_PUBLIC)).unwrap();

        let request = DidExchangeResponseBuilder::new()
            .message(invitation)
            .did("did:key:z6MkpFZ86WuUpihn1mTRbpBCGE6YpCvsBYtZQYnd9jcuAUup".to_string())
            .did_doc(did_doc)
            .build()
            .unwrap();

        assert_eq!(
            request.get_didcomm_header().m_type,
            "https://didcomm.org/didexchange/1.0/request"
        );

        let did_doc = serde_json::to_value(bob_key.get_did_document(CONFIG_LD_PUBLIC)).unwrap();

        let response = DidExchangeResponseBuilder::new()
            .message(request)
            .did("did:key:z6MkpFZ86WuUpihn1mTRbpBCGE6YpCvsBYtZQYnd9jcuAUup".to_string())
            .did_doc(did_doc)
            .build()
            .unwrap();

        assert_eq!(
            response.get_didcomm_header().m_type,
            "https://didcomm.org/didexchange/1.0/response"
        );

        println!("{}", serde_json::to_string_pretty(&response).unwrap());
    }

    #[test]
    fn test_build_complete() {
        let alice_key = generate::<X25519KeyPair>(None);
        let bob_key = generate::<X25519KeyPair>(None);

        let invitation = InvitationBuilder::new()
            .goal("to create a relationship".to_string())
            .goal_code("aries.rel.build".to_string())
            .build()
            .unwrap();

        let did_doc = serde_json::to_value(alice_key.get_did_document(CONFIG_LD_PUBLIC)).unwrap();

        let request = DidExchangeResponseBuilder::new()
            .message(invitation)
            .did("did:key:z6MkpFZ86WuUpihn1mTRbpBCGE6YpCvsBYtZQYnd9jcuAUup".to_string())
            .did_doc(did_doc)
            .build()
            .unwrap();

        assert_eq!(
            request.get_didcomm_header().m_type,
            "https://didcomm.org/didexchange/1.0/request"
        );

        let did_doc = serde_json::to_value(bob_key.get_did_document(CONFIG_LD_PUBLIC)).unwrap();

        let response = DidExchangeResponseBuilder::new()
            .message(request)
            .did("did:key:z6MkpFZ86WuUpihn1mTRbpBCGE6YpCvsBYtZQYnd9jcuAUup".to_string())
            .did_doc(did_doc)
            .build()
            .unwrap();

        assert_eq!(
            response.get_didcomm_header().m_type,
            "https://didcomm.org/didexchange/1.0/response"
        );

        let complete = DidExchangeResponseBuilder::new()
            .message(response)
            .did("did:key:z6MkpFZ86WuUpihn1mTRbpBCGE6YpCvsBYtZQYnd9jcuAUup".to_string())
            .build()
            .unwrap();

        assert_eq!(
            complete.get_didcomm_header().m_type,
            "https://didcomm.org/didexchange/1.0/complete"
        );

        println!("{}", serde_json::to_string_pretty(&complete).unwrap());
    }

    #[tokio::test]
    async fn test_handler() {
        let key = generate::<X25519KeyPair>(None);
        let key_to = generate::<X25519KeyPair>(None);
        let did_to = key_to.get_did_document(Default::default()).id;
        let invitation = InvitationBuilder::new()
            .goal("to create a relationship".to_string())
            .goal_code("aries.rel.build".to_string())
            .build()
            .unwrap();

        let did_doc = serde_json::to_value(key.get_did_document(CONFIG_LD_PUBLIC)).unwrap();

        let request = DidExchangeResponseBuilder::new()
            .message(invitation)
            .did(did_to.to_string())
            .did_doc(did_doc)
            .build()
            .unwrap()
            .from(&did_to);

        assert_eq!(
            request.get_didcomm_header().m_type,
            "https://didcomm.org/didexchange/1.0/request"
        );
        let handler = DidExchangeHandler::default();
        let response = handler.handle(&request, Some(&key), None).await;
        assert_ne!(response.unwrap(), HandlerResponse::Skipped);
    }
}
