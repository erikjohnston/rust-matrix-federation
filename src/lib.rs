
#[macro_use] extern crate log;
#[macro_use] extern crate quick_error;

extern crate serde_json;
extern crate sodiumoxide;
extern crate rustc_serialize;
extern crate chrono;
extern crate openssl;
extern crate serde;

pub mod key;
pub mod signedjson;

use serde_json::builder;


pub fn sign_request_b64(
    key: &signedjson::SigningKey,
    method: String,
    uri: String,
    origin: String,
    destination: String,
    content: Option<&signedjson::Object>,
) -> String {
    let mut builder = builder::ObjectBuilder::new()
        .insert("method", method)
        .insert("uri", uri)
        .insert("origin", origin)
        .insert("destination", destination);

    if let Some(obj) = content {
        builder = builder.insert("content", obj.clone());
    }

    let val = builder.unwrap();

    let obj = val.as_object().unwrap();
    signedjson::get_sig_for_json_b64(key, obj).unwrap()
}


// struct MakeQuery {
//     signing_key: signedjson::SigningKey,
//     server_name: String,
// }
//
// impl MakeQuery {
//     fn make_query(&self) {
//         let path = "/_matrix/federation/v1/query/directory?room_alias=%23test%3Alocalhost%3A8480";
//         let url = "http://localhost:8080".to_string() + path;
//         let client = hyper::Client::new();
//
//         loop {
//             sleep(Duration::from_secs(5));
//
//             info!("Making request");
//
//             let sig = sign_request_b64(
//                 &self.signing_key,
//                 "GET".to_string(),
//                 path.to_string(),
//                 self.server_name.clone(),
//                 "localhost:8480".to_string(),
//                 None,
//             );
//
//             let auth_header = format!(
//                 r#"X-Matrix origin={},key="{}",sig="{}""#,
//                 &self.server_name, self.signing_key.key_id, sig,
//             );
//
//             let response_builder = client.get(&url)
//                 .header(hyper::header::Authorization(auth_header));
//
//             let resp = match response_builder.send() {
//                 Ok(response) => response,
//                 Err(e) => {
//                     error!("Got error when sending request: {}", e.description());
//                     continue;
//                 },
//             };
//
//             if !resp.status.is_success() {
//                 warn!("Got non-200 response: {}", resp.status);
//                 continue;
//             }
//
//             let val : value::Value = serde_json::from_reader(resp).expect("Invalid json response");
//             let room_id = val.find("room_id").expect("Expected room_id")
//                 .as_string().expect("Expected string");
//             println!("room_id: {}", room_id);
//             return;
//         }
//
//     }
// }
