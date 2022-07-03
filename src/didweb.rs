use url::Url;

pub fn url_to_did_web(url: &str) -> String {
    let parsed = Url::parse(url).unwrap();
    let mut did = format!("did:web:{}", parsed.host_str().unwrap());
    did = match parsed.port() {
        Some(443) => did,
        Some(port) => format!("{}%3A{}", did, port),
        None => did,
    };
    did = match parsed.path() {
        "/" => did,
        path => format!("{}{}", did, path.replace('/', ":")),
    };
    did
}

#[test]
fn test_url_to_did_web() {
    assert_eq!(
        "did:web:w3c-ccg.github.io",
        url_to_did_web("http://w3c-ccg.github.io")
    );
    assert_eq!(
        "did:web:w3c-ccg.github.io",
        url_to_did_web("https://w3c-ccg.github.io")
    );
    assert_eq!(
        "did:web:w3c-ccg.github.io:user:alice",
        url_to_did_web("http://w3c-ccg.github.io/user/alice")
    );
    assert_eq!(
        "did:web:example.com%3A3000",
        url_to_did_web("http://example.com:3000")
    );
}
