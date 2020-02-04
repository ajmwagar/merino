use merino::*;

#[test]
/// Can we crate a new `Merino` instance
fn merino_contructor() {
    assert!(Merino::new(1080, "127.0.0.1", Vec::new(), Vec::new()).is_ok())
}

