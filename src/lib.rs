use hex::encode as encode_hex;
use hmac::{Hmac, Mac, NewMac};
use sha2::Sha256;
type HmacSha256 = Hmac<Sha256>;
use constant_time_eq::constant_time_eq;
use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Debug, Display};

#[derive(Debug)]
struct InvalidKeyValuePair;

impl Display for InvalidKeyValuePair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid key value pair")
    }
}
impl Error for InvalidKeyValuePair {}

pub(crate) fn compute_signature(payload: &str, secret: &str) -> String {
    let mut mac = HmacSha256::new_varkey(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(payload.as_bytes());

    let result = mac.finalize();
    let result = result.into_bytes().as_slice().to_vec();

    encode_hex(result)
}

pub(crate) fn parse_stripe_signature_header(
    header: &str,
) -> Result<HashMap<String, String>, Box<dyn Error>> {
    let signature = header.trim().to_string();
    let signature: Vec<&str> = signature.split(",").collect();
    let signature: Vec<Vec<&str>> = signature
        .iter()
        .map(|pair| pair.split("=").map(|s| s.trim()).collect())
        .collect();

    let mut values: HashMap<String, String> = HashMap::new();

    for pair in &signature {
        if pair.len() != 2 {
            return Err(Box::new(InvalidKeyValuePair));
        }

        let key = pair.first();
        let value = pair.last();

        values.insert(key.unwrap().to_string(), value.unwrap().to_string());
    }

    Ok(values)
}

/// Implements Webhook payload verification, in accordance with official Stripe docs.
/// See [docs](https://stripe.com/docs/webhooks/signatures) for details.
///
/// # Errors
///
/// This function will return Err whenever the payload does not contain
/// the required entries (```v1``` and ```t```).
pub fn verify(secret: &str, header: &str, payload: &str) -> Result<bool, Box<dyn Error>> {
    let parsed_header = parse_stripe_signature_header(header)?;

    let received_timestamp = parsed_header.get("t").ok_or(InvalidKeyValuePair)?;
    let received_signature = parsed_header.get("v1").ok_or(InvalidKeyValuePair)?;

    let payload = format!("{}.{}", received_timestamp, payload);
    let expected_signature = &compute_signature(&payload, &secret);

    Ok(constant_time_eq(
        expected_signature.as_bytes(),
        received_signature.as_bytes(),
    ))
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::compute_signature;
    use crate::parse_stripe_signature_header;
    use crate::verify;

    pub(crate) fn generate_test_header(payload: String) -> String {
        let start = SystemTime::now();
        let timestamp = start
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_secs()
            .to_string();

        let payload = format!("{}.{}", timestamp, payload);
        let signature = compute_signature(&payload, "really secure secret");

        let header = format!("t={},v1={},v0=", timestamp, signature);

        return header;
    }

    #[test]
    fn it_parses_stripe_signature_header() {
        let stripe_signature_header = generate_test_header("sample payload".to_string());
        dbg!(&stripe_signature_header);

        let values = parse_stripe_signature_header(&stripe_signature_header).unwrap();

        assert!(values.get("t").is_some());
        assert!(values.get("v1").is_some());

        assert!(verify(
            "really secure secret",
            &stripe_signature_header,
            "sample payload",
        )
        .unwrap());
    }
}
