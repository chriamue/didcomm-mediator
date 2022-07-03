// https://www.w3.org/TR/did-core/#did-document-properties
use did_key::{DIDCore, KeyPair, CONFIG_LD_PUBLIC};
#[cfg(feature = "iota")]
use identity_iota::prelude::*;
use serde_json::Value;

#[derive(Default)]
pub struct DidDocBuilder {
    did: Option<String>,
    keypair: Option<KeyPair>,
    endpoint: Option<String>,
    #[cfg(feature = "iota")]
    iota_document: Option<IotaDocument>,
}

impl DidDocBuilder {
    pub fn new() -> Self {
        DidDocBuilder {
            did: None,
            keypair: None,
            endpoint: None,
            #[cfg(feature = "iota")]
            iota_document: None,
        }
    }

    pub fn did(&mut self, did: String) -> &mut Self {
        self.did = Some(did);
        self
    }

    pub fn keypair(&mut self, keypair: KeyPair) -> &mut Self {
        self.keypair = Some(keypair);
        self
    }

    pub fn endpoint(&mut self, endpoint: String) -> &mut Self {
        self.endpoint = Some(endpoint);
        self
    }

    #[cfg(feature = "iota")]
    pub fn iota_document(&mut self, iota_document: IotaDocument) -> &mut Self {
        self.iota_document = Some(iota_document);
        self
    }

    pub fn build(&mut self) -> Result<Value, &'static str> {
        let mut did_doc = self
            .keypair
            .as_ref()
            .unwrap()
            .get_did_document(CONFIG_LD_PUBLIC);
        did_doc.verification_method[0].private_key = None;
        let did_key = &did_doc.id;
        let mut did_doc = serde_json::to_value(&did_doc).unwrap();
        did_doc["id"] = serde_json::to_value(self.did.as_ref().unwrap()).unwrap();
        match &self.endpoint {
            Some(endpoint) => {
                did_doc["service"] = serde_json::json!([
                  {
                    "id": format!("{}#endpoint", did_key),
                    "serviceEndpoint": [
                  {
                    "uri": endpoint,
                    "accept": [
                        "didcomm/v2"
                    ],
                    "recipientKeys": [did_key]
                  },
                  ],
                    "type": "did-communication"
                  },
                ]);
                #[cfg(feature = "iota")]
                {
                    if self.iota_document.is_some() {
                        match self.iota_document.as_ref().unwrap().service().first() {
                            Some(service) => did_doc["service"]
                                .as_array_mut()
                                .unwrap()
                                .push(serde_json::to_value(service).unwrap()),
                            None => {}
                        }
                    }
                }
            }
            None => {}
        }
        #[cfg(feature = "iota")]
        {
            if self.iota_document.is_some() {
                match self
                    .iota_document
                    .as_ref()
                    .unwrap()
                    .core_document()
                    .verification_method()
                    .first()
                {
                    Some(verification_method) => did_doc["verificationMethod"]
                        .as_array_mut()
                        .unwrap()
                        .push(serde_json::to_value(verification_method).unwrap()),
                    None => {}
                }
            }
        }

        Ok(did_doc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use base58::FromBase58;
    use did_key::{generate, X25519KeyPair};
    use rocket;

    #[test]
    fn test_build_diddoc() {
        let rocket = rocket::build();
        let figment = rocket.figment();
        let config: Config = figment.extract().expect("config");

        let keypair =
            generate::<X25519KeyPair>(Some(&config.key_seed.unwrap().from_base58().unwrap()));

        let did = "did:web:example.com".to_string();

        let did_doc = DidDocBuilder::new()
            .did(did.to_string())
            .keypair(keypair)
            .build()
            .unwrap();

        assert_eq!(
            did_doc.get("id").unwrap(),
            &serde_json::to_value(&did).unwrap()
        );
        assert!(did_doc.get("verificationMethod").is_some());
        assert!(did_doc.get("service").is_none());
        println!("{}", serde_json::to_string_pretty(&did_doc).unwrap())
    }

    #[test]
    fn test_build_diddoc_with_service() {
        let rocket = rocket::build();
        let figment = rocket.figment();
        let config: Config = figment.extract().expect("config");

        let keypair =
            generate::<X25519KeyPair>(Some(&config.key_seed.unwrap().from_base58().unwrap()));
        let did = "did:web:example.com".to_string();
        let did_doc = DidDocBuilder::new()
            .did(did)
            .keypair(keypair)
            .endpoint(config.ext_service)
            .build()
            .unwrap();

        assert!(did_doc.get("verificationMethod").is_some());
        assert!(did_doc.get("service").is_some());
    }

    #[cfg(feature = "iota")]
    #[tokio::test]
    async fn test_build_iota_diddoc() {
        use identity_iota::client::ResolvedIotaDocument;
        use identity_iota::client::Resolver;
        use identity_iota::iota_core::IotaDID;
        use std::str::FromStr;

        let rocket = rocket::build();
        let figment = rocket.figment();
        let config: Config = figment.extract().expect("config");

        let did = IotaDID::from_str(config.did_iota.as_ref().unwrap()).unwrap();

        let resolver: Resolver = Resolver::new().await.unwrap();
        let resolved_did_document: ResolvedIotaDocument = resolver.resolve(&did).await.unwrap();
        let document = resolved_did_document.document;

        let keypair =
            generate::<X25519KeyPair>(Some(&config.key_seed.unwrap().from_base58().unwrap()));
        let did = "did:web:example.com".to_string();
        let did_doc = DidDocBuilder::new()
            .did(did)
            .iota_document(document)
            .keypair(keypair)
            .endpoint(config.ext_service)
            .build()
            .unwrap();

        assert!(did_doc.get("verificationMethod").is_some());
        assert!(did_doc.get("service").is_some());
        println!("{}", serde_json::to_string_pretty(&did_doc).unwrap())
    }
}
