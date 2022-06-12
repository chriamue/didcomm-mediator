use crate::resolver::resolve;
use base58::ToBase58;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Service {
    pub id: String,
    #[serde(rename = "recipientKeys")]
    pub recipient_keys: Vec<String>,
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
    #[serde(rename = "type")]
    pub typ: String,
}

impl Service {
    pub async fn new(did: String, endpoint: String) -> Result<Self, Box<dyn std::error::Error>> {
        let id = format!("{}#didcomm", did);
        let pub_key = resolve(&did).await.unwrap_or_default().to_base58();
        Ok(Service {
            id,
            recipient_keys: vec![pub_key],
            service_endpoint: endpoint,
            typ: "did-communication".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base58::FromBase58;
    use did_key::{generate, DIDCore, KeyFormat::Base58, X25519KeyPair};

    #[tokio::test]
    async fn new_service() {
        let seed = "HBTcN2MrXNRj9xF9oi8QqYyuEPv3JLLjQKuEgW9oxVKP";
        let private = seed.from_base58().unwrap();
        let keypair = generate::<X25519KeyPair>(Some(&private));

        let did = keypair.get_did_document(Default::default()).id;
        let endpoint = "https://example.com".to_string();

        let service = Service::new(did, endpoint.to_string()).await.unwrap();
        assert_eq!(service.service_endpoint, endpoint);
        assert_eq!(
            &Base58(service.recipient_keys[0].to_string()),
            keypair
                .get_did_document(Default::default())
                .verification_method[0]
                .public_key
                .as_ref()
                .unwrap()
        );
        println!("{:?}", service);
    }
}
