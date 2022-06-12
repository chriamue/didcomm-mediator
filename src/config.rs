use serde::Deserialize;
#[derive(PartialEq, Deserialize, Clone)]
pub struct Config {
    pub ident: String,
    pub ext_hostname: String,
    pub ext_service: String,
    pub wallet_path: Option<String>,
    pub wallet_password: Option<String>,
    pub key_seed: Option<String>,
    pub did_key: Option<String>,
    #[cfg(feature = "iota")]
    pub did_iota: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            ident: "".to_string(),
            ext_hostname: "".to_string(),
            ext_service: "".to_string(),
            wallet_path: Some("wallet.hold.example".to_string()),
            wallet_password: Some("changeme".to_string()),
            key_seed: Some("293WPZ2PJQmNFN3MCMu49RM6ukVEQkfM1aJp9gJ8JhAs".to_string()),
            did_key: Some("did:key:z6LSp5C8TjVvzJx3Kh5MFcdkHit6CVKTQ9RmTr3jLyE77BfH".to_string()),
            #[cfg(feature = "iota")]
            did_iota: Some("did:iota:11PwbeZDPtksuh5rTojk7eALu7R7adYQkBakt49tQE7".to_string()),
        }
    }
}
