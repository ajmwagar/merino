use merino::*;

#[tokio::test]
/// Can we crate a new `Merino` instance
async fn merino_contructor() {
    assert!(Merino::new(1080, "127.0.0.1", Vec::new(), Vec::new(), None)
        .await
        .is_ok())
}
