use crate::config::Config;
use base58::{FromBase58, ToBase58};
use did_key::{generate, DIDCore, KeyMaterial, KeyPair, X25519KeyPair};
#[cfg(feature = "iota")]
use identity_iota::prelude::*;

pub struct Wallet {
    pub seed: String,
    #[cfg(feature = "iota")]
    pub account: Option<identity_iota::account::Account>,
}

impl Default for Wallet {
    fn default() -> Self {
        let key = generate::<X25519KeyPair>(None);
        let seed = key.private_key_bytes().to_base58();
        Wallet::new(Some(seed))
    }
}

impl Wallet {
    pub fn new(seed: Option<String>) -> Self {
        match seed {
            Some(seed) => Wallet {
                seed,
                #[cfg(feature = "iota")]
                account: None,
            },
            _ => Wallet::default(),
        }
    }

    pub async fn new_from_config(config: &Config) -> Result<Self, Box<dyn std::error::Error>> {
        match config.key_seed.clone() {
            Some(seed) => Ok(Wallet {
                seed,
                #[cfg(feature = "iota")]
                account: Some(Self::load_iota_account(config).await?),
            }),
            _ => Ok(Wallet::default()),
        }
    }

    pub fn keypair(&self) -> KeyPair {
        generate::<X25519KeyPair>(Some(&self.seed.from_base58().unwrap()))
    }

    pub fn did_key(&self) -> String {
        self.keypair().get_did_document(Default::default()).id
    }

    #[cfg(feature = "iota")]
    pub fn did_iota(&self) -> Option<String> {
        self.account
            .as_ref()
            .map(|account| account.did().to_string())
    }

    #[cfg(feature = "iota")]
    async fn update_iota_key(
        account: &mut identity_iota::account::Account,
        key: identity_iota::crypto::PublicKey,
    ) {
        account
            .update_identity()
            .create_method()
            .content(identity_iota::account::MethodContent::PublicX25519(key))
            .fragment("kex-0")
            .apply()
            .await
            .unwrap();
    }

    #[cfg(feature = "iota")]
    async fn load_iota_account(
        config: &Config,
    ) -> Result<identity_iota::account::Account, Box<dyn std::error::Error>> {
        use identity_iota::account::Account;
        use identity_iota::account::AutoSave;
        use identity_iota::account::IdentitySetup;
        use identity_iota::account_storage::Stronghold;
        use identity_iota::iota_core::IotaDID;

        let account = match (&config.key_seed, &config.did_iota) {
            (_, Some(did)) => {
                let did_iota: IotaDID = IotaDID::try_from(did.to_string()).unwrap();
                Account::builder()
                    .autosave(AutoSave::Every)
                    .storage(
                        Stronghold::new(
                            &config.wallet_path.clone().unwrap(),
                            config.wallet_password.clone().unwrap(),
                            None,
                        )
                        .await?,
                    )
                    .autopublish(true)
                    .load_identity(did_iota)
                    .await?
            }
            (Some(seed), _) => {
                let private = seed.from_base58().unwrap();
                let keypair_ed = identity_iota::prelude::KeyPair::try_from_private_key_bytes(
                    KeyType::Ed25519,
                    &private,
                )
                .unwrap();
                let id_setup = IdentitySetup::new().private_key(keypair_ed.private().clone());
                let mut account = Account::builder()
                    .autosave(AutoSave::Every)
                    .storage(
                        Stronghold::new(
                            &config.wallet_path.clone().unwrap(),
                            config.wallet_password.clone().unwrap(),
                            None,
                        )
                        .await?,
                    )
                    .autopublish(true)
                    .create_identity(id_setup)
                    .await?;
                println!("created new identity: {:?}", account.did());
                let keypair = identity_iota::prelude::KeyPair::try_from_private_key_bytes(
                    KeyType::X25519,
                    &private,
                )
                .unwrap();
                Self::update_iota_key(&mut account, keypair.public().clone()).await;
                account
            }
            (_, _) => {
                Account::builder()
                    .autosave(AutoSave::Every)
                    .storage(
                        Stronghold::new(
                            &config.wallet_path.clone().unwrap(),
                            config.wallet_password.clone().unwrap(),
                            None,
                        )
                        .await?,
                    )
                    .autopublish(true)
                    .create_identity(IdentitySetup::default())
                    .await?
            }
        };
        Ok(account)
    }

    pub fn log(&self) {
        println!("did key: {}", self.did_key());
        #[cfg(feature = "iota")]
        {
            use identity_iota::client::ExplorerUrl;
            let explorer: &ExplorerUrl = ExplorerUrl::mainnet();
            if self.account.is_some() {
                println!("did iota: {}", self.account.as_ref().unwrap().did());
                println!(
                    "Explore the DID Document = {}",
                    explorer
                        .resolver_url(self.account.as_ref().unwrap().did())
                        .unwrap()
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default() {
        let wallet = Wallet::default();
        assert_ne!(wallet.seed, "");
    }

    #[test]
    fn test_new() {
        let wallet1 = Wallet::default();
        let wallet2 = Wallet::new(Some(wallet1.seed.to_string()));
        assert_eq!(wallet1.seed, wallet2.seed);
    }

    #[test]
    fn test_did_key() {
        let wallet = Wallet::default();
        assert_ne!(wallet.keypair().private_key_bytes(), Vec::<u8>::new());
    }

    #[tokio::test]
    async fn test_new_from_config() {
        let mut config = Config::default();
        let wallet1 = Wallet::new_from_config(&config).await.unwrap();
        wallet1.log();
        config.key_seed = None;
        let wallet2 = Wallet::new_from_config(&config).await.unwrap();

        #[cfg(feature = "iota")]
        {
            assert_eq!(wallet1.did_iota().unwrap(), config.did_iota.unwrap());
            assert_eq!(wallet2.did_iota(), None);
            assert_ne!(wallet1.seed, "");
            let mut config = Config::default();
            config.did_iota = None;
            assert!(Wallet::new_from_config(&config).await.is_err());
        }
    }
}
