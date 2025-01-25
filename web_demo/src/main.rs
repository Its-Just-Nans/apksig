#![recursion_limit = "1024"]

use apksig::SigningBlock;
use console_error_panic_hook::set_once as set_panic_hook;
use serde_json::Value;
use wasm_bindgen::prelude::*;
use web_sys::window;

#[wasm_bindgen]
pub fn process_file(data: &[u8]) {
    let file_len = data.len();
    let reader = std::io::Cursor::new(&data[..]);
    let res_sig = SigningBlock::extract(reader, file_len, 0);
    web_sys::console::log_1(&"Finished".into());
    match res_sig {
        Ok(sig) => {
            web_sys::console::log_1(&"Success".into());
            display_signature(&sig);
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
                html.push_str(&format!(
                    "<span>[{}]</span>",
                    arr.iter()
                        .map(format_json_value)
                        .collect::<Vec<String>>()
                        .join(", ")
                ));
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
