#![recursion_limit = "1024"]

use apksig::SigningBlock;
use console_error_panic_hook::set_once as set_panic_hook;
use serde_json::Value;
use wasm_bindgen::prelude::*;
use web_sys::window;

include!("../../tests/raw_signing_block_v2.rs");

#[wasm_bindgen]
pub fn process_demo() -> String {
    return process_file(&BLOCK);
}

#[wasm_bindgen]
pub fn process_file(data: &[u8]) -> String {
    let res_sig = SigningBlock::from_u8(data);
    web_sys::console::log_1(&"Finished".into());
    match res_sig {
        Ok(sig) => {
            web_sys::console::log_1(&"Success".into());
            display_signature(&sig);
            return serde_json::to_string(&sig).expect("Error serializing data");
        }
        Err(e) => {
            let error = format!("Error: {}", e.to_string());
            web_sys::console::log_1(&error.clone().into());
            let document = window()
                .and_then(|win| win.document())
                .expect("Could not access document");
            let drop_handler = document
                .get_element_by_id("dropHandler")
                .expect("Could not find #dropHandler");
            drop_handler.set_inner_html("");
            let div_helper = document
                .create_element("div")
                .expect("Could not create element");
            div_helper.set_inner_html(&error);
            div_helper.set_class_name("error");
            drop_handler
                .append_child(&div_helper)
                .expect("Failed to append text");
        }
    }
    return "{\"error\": \"Error processing file\"}".to_string();
}

fn multi_sha(data: &[u8]) -> (String, String, String) {
    use sha1::{Digest, Sha1};
    use sha2::Sha256;
    use std::fmt::Write;

    let mut hasher = Sha256::new();
    hasher.update(data);
    let sha256 = hasher.finalize().to_vec();
    let md5 = md5::compute(data).to_vec();
    let mut hasher = Sha1::new();
    hasher.update(data);
    let sha1 = hasher.finalize().to_vec();
    (
        sha256.iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        }),
        md5.iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        }),
        sha1.iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        }),
    )
}

fn display_signature(sig: &SigningBlock) {
    let json = serde_json::to_value(sig).expect("Error serializing data");
    let html = generate_recursive_html(&json);

    let document = window()
        .and_then(|win| win.document())
        .expect("Could not access document");
    let drop_handler = document
        .get_element_by_id("dropHandler")
        .expect("Could not find #dropHandler");
    drop_handler.set_inner_html("");
    let div_helper = document
        .create_element("div")
        .expect("Could not create element");
    div_helper.set_inner_html("APK Signing Block. Click on values to copy them to clipboard");
    div_helper.set_class_name("success");
    drop_handler
        .append_child(&div_helper)
        .expect("Failed to append text");
    let div = document
        .create_element("div")
        .expect("Could not create element");
    div.set_inner_html(&html);
    drop_handler
        .append_child(&div)
        .expect("Failed to append text");
}

// This function generates the HTML recursively
fn generate_recursive_html(json: &Value) -> String {
    match json {
        Value::Object(obj) => {
            let mut html = String::new();
            for (key, value) in obj {
                html.push_str(&format!("<details><summary>{}</summary>", key));
                html.push_str(&generate_recursive_html(value));
                html.push_str("</details>");
            }
            html
        }
        Value::Array(arr) => {
            let mut html = String::new();
            // check if elements are numbers
            let all_numbers = arr.iter().all(|x| x.is_number());
            if all_numbers {
                html.push_str(&format!("<span>len: {}</span>", arr.len()));
                if !arr.is_empty() {
                    let (sha256, md5, sha1) = multi_sha(
                        &arr.iter()
                            .map(|x| x.as_u64().unwrap() as u8)
                            .collect::<Vec<u8>>(),
                    );
                    html.push_str(&format!(
                        "<details><summary>SHA256</summary><span>{}</span></details>",
                        sha256
                    ));
                    html.push_str(&format!(
                        "<details><summary>MD5</summary><span>{}</span></details>",
                        md5
                    ));
                    html.push_str(&format!(
                        "<details><summary>SHA1</summary><span>{}</span></details>",
                        sha1
                    ));
                    html.push_str(&format!(
                        "<details><summary>[u8]</summary><span>[{}]</span></details>",
                        arr.iter()
                            .map(format_json_value)
                            .collect::<Vec<String>>()
                            .join(", ")
                    ));
                    html.push_str(&format!(
                        "<details><summary>binary</summary><span>{}</span></details>",
                        arr.iter()
                            .map(|x| format!("{:08b}", x.as_u64().unwrap()))
                            .collect::<Vec<String>>()
                            .join("")
                    ));
                    html.push_str(&format!(
                        "<details><summary>hex</summary><span>{}</span></details>",
                        arr.iter()
                            .map(|x| format!("{:02x}", x.as_u64().unwrap()))
                            .collect::<Vec<String>>()
                            .join("")
                    ));
                    if let Ok(res) =
                        String::from_utf8(arr.iter().map(|x| x.as_u64().unwrap() as u8).collect())
                    {
                        if !res.trim().trim_matches(char::from(0)).is_empty() {
                            html.push_str(&format!(
                                "<details><summary>string</summary><span>{}</span></details>",
                                res
                            ));
                        }
                    }
                }
            } else {
                for (i, value) in arr.iter().enumerate() {
                    html.push_str(&format!("<details><summary>Item {}</summary>", i + 1));
                    html.push_str(&generate_recursive_html(value));
                    html.push_str("</details>");
                }
            }
            html
        }
        Value::String(s) => format!("<span>{}</span>", s.clone()),
        Value::Number(n) => format!("<span>{}</span>", n.to_string()),
        Value::Bool(b) => format!("<span>{}</span>", b.to_string()),
        Value::Null => format!("<span>{}</span>", "null".to_string()),
    }
}

fn format_json_value(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
        Value::Array(arr) => format!(
            "[{}]",
            arr.iter()
                .map(format_json_value)
                .collect::<Vec<String>>()
                .join(", ")
        ),
        Value::Object(obj) => format!(
            "{{ {} }}",
            obj.iter()
                .map(|(k, v)| format!("{}: {}", k, format_json_value(v)))
                .collect::<Vec<String>>()
                .join(", ")
        ),
    }
}

fn main() {
    set_panic_hook();
}
