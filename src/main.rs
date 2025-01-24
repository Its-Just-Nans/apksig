fn main() {
    match apksig::real_main() {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("Error: {:?}", e);
            std::process::exit(1);
        }
    }
}
