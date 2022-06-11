use crate::config::Config;
use base58::{FromBase58, ToBase58};
use did_key::{generate, KeyMaterial, KeyPair, X25519KeyPair};
#[cfg(feature = "iota")]
use identity::prelude::*;

pub struct Wallet {
    pub seed: String,
    #[cfg(feature = "iota")]
    pub account: Option<identity::account::Account>,
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

    pub async fn new_from_config(config: &Config) -> Self {
        match config.key_seed.clone() {
            Some(seed) => Wallet {
                seed,
                #[cfg(feature = "iota")]
                account: Some(Self::load_iota_account(config).await.unwrap()),
            },
            _ => Wallet::default(),
        }
    }

    pub fn keypair(&self) -> KeyPair {
        generate::<X25519KeyPair>(Some(&self.seed.from_base58().unwrap()))
    }

    #[cfg(feature = "iota")]
    pub fn did_iota(&self) -> KeyPair {
        generate::<X25519KeyPair>(Some(&self.seed.from_base58().unwrap()))
    }

    #[cfg(feature = "iota")]
    async fn load_iota_account(
        config: &Config,
    ) -> Result<identity::account::Account, Box<dyn std::error::Error>> {
        use identity::account::Account;
        use identity::account::AutoSave;
        use identity::account::IdentitySetup;
        use identity::account::MethodContent;
        use identity::account_storage::Stronghold;
        use identity::iota_core::IotaDID;

        let account = match (&config.key_seed, &config.did_iota) {
            (Some(seed), Some(did)) => {
                let did_iota: IotaDID = IotaDID::try_from(did.to_string()).unwrap();
                Account::builder()
                    .autosave(AutoSave::Every)
                    .storage(
                        Stronghold::new(
                            &config.wallet_path.clone().unwrap(),
                            config.wallet_password.clone().unwrap(),
                            None,
                        )
                        .await
                        .unwrap(),
                    )
                    .autopublish(true)
                    .load_identity(did_iota)
                    .await
                    .unwrap()
            }
            (Some(seed), Some(did)) => {
                let private = seed.from_base58().unwrap();
                let keypair_ed = identity::prelude::KeyPair::try_from_private_key_bytes(
                    KeyType::Ed25519,
                    &private,
                )
                .unwrap();
                let id_setup = IdentitySetup::new().private_key(keypair_ed.private().clone());
                let account = Account::builder()
                    .autosave(AutoSave::Every)
                    .storage(
                        Stronghold::new(
                            &config.wallet_path.clone().unwrap(),
                            config.wallet_password.clone().unwrap(),
                            None,
                        )
                        .await
                        .unwrap(),
                    )
                    .autopublish(true)
                    .create_identity(id_setup)
                    .await
                    .unwrap();
                println!("created new identity: {:?}", account.did());
                account
            }
            (_, _) => Account::builder()
                .autosave(AutoSave::Every)
                .storage(
                    Stronghold::new(
                        &config.wallet_path.clone().unwrap(),
                        config.wallet_password.clone().unwrap(),
                        None,
                    )
                    .await
                    .unwrap(),
                )
                .autopublish(true)
                .create_identity(IdentitySetup::default())
                .await
                .unwrap(),
        };

        Ok(account)
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

        let wallet = Wallet::new(None);
        assert_ne!(wallet.seed, "");
    }

    #[test]
    fn test_did_key() {
        let wallet = Wallet::default();
        assert_ne!(wallet.keypair().private_key_bytes(), Vec::<u8>::new());
    }
}
