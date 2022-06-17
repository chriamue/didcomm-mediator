use identity_iota::client::Resolver;
use identity_iota::did::MethodScope;
use identity_iota::iota_core::IotaDID;
use std::error::Error;
use std::str::FromStr;

pub async fn resolve(did: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let resolver: Resolver = Resolver::new().await.unwrap();
    let did = IotaDID::from_str(did).unwrap();
    let document = resolver.resolve(&did).await?;
    match document
        .document
        .resolve_method("kex-0", Some(MethodScope::VerificationMethod))
    {
        Some(method) => Ok(method.data().try_decode().unwrap()),
        None => Err(Box::new(identity_iota::iota_core::Error::MissingSigningKey)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base58::FromBase58;
    use identity_iota::prelude::KeyPair;
    use identity_iota::prelude::*;

    #[tokio::test]
    async fn test_resolve() {
        let seed = "CLKmgQ7NbRw3MpGu47TiSjQknGf2oBPnW9nFygzBkh9h";
        let private = seed.from_base58().unwrap();
        let did = "did:iota:HcFFrR72GJq2hXuwbz2UwE7wkDE2VRkX2NwHeSVroeUH".to_string();

        let keypair = KeyPair::try_from_private_key_bytes(KeyType::X25519, &private).unwrap();

        let public_key = resolve(&did).await.unwrap();

        assert_eq!(keypair.public().as_ref(), public_key);
    }
}
