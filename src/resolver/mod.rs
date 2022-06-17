#[cfg(feature = "iota")]
pub mod iota_resolver;
pub mod key_resolver;

#[derive(Debug)]
pub enum ResolveError {
    KeyResolveError(didcomm_rs::Error),
    #[cfg(feature = "iota")]
    IotaResolveError(Box<dyn std::error::Error>),
}

pub async fn resolve(did: &str) -> Result<Vec<u8>, ResolveError> {
    if did.starts_with("did:key:") {
        return match key_resolver::resolve(did).await {
            Ok(public_key) => Ok(public_key),
            Err(err) => Err(ResolveError::KeyResolveError(err)),
        };
    }
    #[cfg(feature = "iota")]
    {
        if did.starts_with("did:iota") {
            return match iota_resolver::resolve(did).await {
                Ok(public_key) => Ok(public_key),
                Err(err) => Err(ResolveError::IotaResolveError(err)),
            };
        }
    }
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base58::FromBase58;
    use did_key::{generate, DIDCore, KeyMaterial, X25519KeyPair};

    #[tokio::test]
    async fn test_resolve() {
        let seed = "HBTcN2MrXNRj9xF9oi8QqYyuEPv3JLLjQKuEgW9oxVKP";
        let private = seed.from_base58().unwrap();
        let keypair = generate::<X25519KeyPair>(Some(&private));
        let did_doc = keypair.get_did_document(Default::default());
        let did = did_doc.id;

        let resolved = resolve(&did).await.unwrap();
        assert_eq!(resolved, keypair.public_key_bytes());
    }
}
