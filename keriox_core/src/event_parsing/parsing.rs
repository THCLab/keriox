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

/// Parses the number from radix 64 using digits from url-safe base64 (`A` = 0, `_` = 63)
pub fn b64_to_num(b64: &[u8]) -> Result<u16, Error> {
    let slice = from_text_to_bytes(b64)?;
    let len = slice.len();

    Ok(u16::from_be_bytes(match len {
        0 => [0u8; 2],
        1 => [0, slice[0]],
        _ => [slice[len - 2], slice[len - 1]],
    }))
}

/// Formats the number in radix 64 using digits from url-safe base64 (`A` = 0, `_` = 63)
pub fn num_to_b64(num: u16) -> String {
    let b64 = from_bytes_to_text(&num.to_be_bytes().to_vec());
    // remove leading A's
    if num < 64 {
        b64[3..].to_string()
    } else if num < 4096 {
        b64[2..].to_string()
    } else {
        todo!()
    }
}

pub fn adjust_with_num(sn: u16, expected_length: usize) -> String {
    if expected_length > 0 {
        let i = num_to_b64(sn);
        if i.len() < expected_length {
            // refill string to have proper size
            let missing_part = "A".repeat(expected_length - i.len());
            [missing_part, i].join("")
        } else {
            [i].join("")
        }
    } else {
        "".to_string()
    }
}

#[test]
fn num_to_b64_test() {
    assert_eq!("A", num_to_b64(0));
    assert_eq!("B", num_to_b64(1));
    assert_eq!("C", num_to_b64(2));
    assert_eq!("D", num_to_b64(3));
    assert_eq!("b", num_to_b64(27));
    assert_eq!("BQ", num_to_b64(80));
    assert_eq!("__", num_to_b64(4095));
}

#[test]
fn b64_to_num_test() {
    assert_eq!(b64_to_num("AAAA".as_bytes()).unwrap(), 0);
    assert_eq!(b64_to_num("A".as_bytes()).unwrap(), 0);
    assert_eq!(b64_to_num("B".as_bytes()).unwrap(), 1);
    assert_eq!(b64_to_num("C".as_bytes()).unwrap(), 2);
    assert_eq!(b64_to_num("D".as_bytes()).unwrap(), 3);
    assert_eq!(b64_to_num("b".as_bytes()).unwrap(), 27);
    assert_eq!(b64_to_num("BQ".as_bytes()).unwrap(), 80);
    assert_eq!(b64_to_num("__".as_bytes()).unwrap(), 4095);
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

#[test]
fn test_adjust_with_num() {
    assert_eq!(adjust_with_num(2, 4), "AAAC");
    assert_eq!(adjust_with_num(27, 6), "AAAAAb");
}
