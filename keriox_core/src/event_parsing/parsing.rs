use base64::{encode_config, URL_SAFE};

use super::error::Error;

pub fn from_text_to_bytes(text: &[u8]) -> Result<Vec<u8>, Error> {
    let lead_size = (4 - (text.len() % 4)) % 4;
    let full_derivative = ["A".repeat(lead_size).as_bytes(), text].concat();

    Ok(base64::decode_config(full_derivative, URL_SAFE)?.to_vec())
}

pub fn from_bytes_to_text(bytes: &[u8]) -> String {
    let lead_size = (3 - (bytes.len() % 3)) % 3;
    let full_derivative: Vec<_> = std::iter::repeat(0)
        .take(lead_size)
        .chain(bytes.to_vec().into_iter())
        .collect();

    encode_config(full_derivative, base64::URL_SAFE)
}

#[test]
fn test_from_text_to_bytes() {
    assert_eq!(
        hex::encode(from_text_to_bytes("MP__".as_bytes()).unwrap()),
        "30ffff"
    );
    assert_eq!(
        hex::encode(from_text_to_bytes("MAAA".as_bytes()).unwrap()),
        "300000"
    );
    assert_eq!(
        hex::encode(from_text_to_bytes("MAAB".as_bytes()).unwrap()),
        "300001"
    );
}

#[test]
fn test_from_bytes_to_text() {
    let b_bytes = from_text_to_bytes("B".as_bytes()).unwrap();
    assert_eq!("AAAB", from_bytes_to_text(&b_bytes));

    assert_eq!(
        from_bytes_to_text(&hex::decode("300000").unwrap()),
        "MAAA".to_string()
    );
    assert_eq!(
        from_bytes_to_text(&hex::decode("300001").unwrap()),
        "MAAB".to_string()
    );
    assert_eq!(
        from_bytes_to_text(&hex::decode("30ffff").unwrap()),
        "MP__".to_string()
    );
}
