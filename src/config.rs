use serde::Deserialize;
#[derive(Default, PartialEq, Deserialize)]
pub struct Config {
    pub ident: String,
    pub ext_hostname: String,
    pub ext_service: String,
    pub key_seed: Option<String>,
    pub did_key: Option<String>,
    #[cfg(feature = "iota")]
    pub did_iota: Option<String>,
}
