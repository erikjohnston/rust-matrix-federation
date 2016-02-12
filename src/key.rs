
use signedjson;

use serde_json::{value, builder};
use chrono;
use chrono::{Timelike, TimeZone};


pub fn key_server_response<TZ: chrono::TimeZone>(
        key: &signedjson::SigningKey,
        server_name: &String,
        valid_until: &chrono::DateTime<TZ>,
        tls_fingerprint_type: String,
        tls_fingerprint_hash: String,
) -> signedjson::Result<value::Value> {
    let valid_until_ts = valid_until.timestamp() * 1000 + valid_until.time().nanosecond() as i64 / 1000000;

    let mut val = builder::ObjectBuilder::new()
        .insert("server_name", server_name)
        .insert("valid_until_ts", valid_until_ts)
        .insert_object("verify_keys", |builder| {
            builder.insert_object(&key.key_id[..], |builder| {
                builder.insert("key", key.public_key_b64())
            })
        })
        .insert_array("tls_fingerprints", |builder| {
            builder.push_object(
                |builder| builder.insert(tls_fingerprint_type, tls_fingerprint_hash)
            )
        })
        .insert_object("old_verify_keys", |builder| builder)
        .unwrap();

    try!(signedjson::sign_json(
        key, server_name.clone(), val.as_object_mut().unwrap()
    ));

    Ok(val)
}


#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;
    use ::signedjson;
    use chrono;
    use chrono::offset::TimeZone;

    #[test]
    fn test_key_server_response() {
        let expected = r#"{"old_verify_keys":{},"server_name":"localhost:8480","signatures":{"localhost:8480":{"ed25519:a_VVEI":"Rxux9EmIhQbzoyEsKTSxEblrgzIWJf9+Lt2Mosck/oVr8wMD4o43aPlUR7KLY9th5/pkA8KSDHgWykuP66jwDw"}},"tls_fingerprints":[{"sha256":"UifzuekNGuXx1QA1tW8j6GCN5VEgI0bRahv3kDWAdDQ"}],"valid_until_ts":1454868565824,"verify_keys":{"ed25519:a_VVEI":{"key":"C7zW67apLhBsUFnDty8ILE380Wke56EqjgykGFKttFk"}}}"#;

        let server_name = "localhost:8480".to_string();
        let seed = b"\xea\xa7\xeb\xc5\\<8\x1f>\xaf\xf0o\xf8\xbf\x12\xf1\x08~\"\xf6\'~d\x84k\"\xef#\x02Nc\x89";
        let signing_key = signedjson::SigningKey::from_seed(seed, "ed25519:a_VVEI".to_string()).expect("Failed to decode seed");

        let valid_until = chrono::UTC.ymd(2016, 02, 07).and_hms_milli(18, 09, 25, 824);

        let resp = key_server_response(
            &signing_key,
            &server_name,
            &valid_until,
            "sha256".to_string(),
            "UifzuekNGuXx1QA1tW8j6GCN5VEgI0bRahv3kDWAdDQ".to_string(),
        ).unwrap();

        assert_eq!(expected, serde_json::to_string(&resp).unwrap());
    }
}
