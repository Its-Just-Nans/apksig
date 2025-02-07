use apksig::SigningBlock;
use std::fs::File;
use std::io::BufReader;
use std::io::Seek;
use std::io::SeekFrom;
use std::path::Path;

fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args.len() < 2 {
        if let Some(progrm) = args.first() {
            eprintln!("Usage: {} <filename>", progrm);
        } else {
            eprintln!("Usage: apksig <filename>");
        }
        std::process::exit(1);
    }
    let filename_args = match args.get(1) {
        Some(fname) => fname,
        None => {
            eprintln!("Error: No filename provided");
            std::process::exit(1);
        }
    };
    let file_path = Path::new(&filename_args);
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error: {:?}", e);
            std::process::exit(1);
        }
    };
    let mut reader = BufReader::new(file);

    let file_len = match reader.seek(SeekFrom::End(0)) {
        Ok(len) => len as usize,
        Err(e) => {
            eprintln!("Error: {:?}", e);
            std::process::exit(1);
        }
    };
    println!("{} length: {} bytes", file_path.display(), file_len);
    match SigningBlock::from_reader(reader, file_len, 0) {
        Ok(sig_block) => {
            println!(
                "APK Signing Block is between {} and {} with a size of {} bytes",
                sig_block.file_offset_start,
                sig_block.file_offset_end,
                sig_block.size_of_block_start + 8
            );
        }
        Err(e) => {
            eprintln!("Error parsing APK Signing Block: {:?}", e);
            std::process::exit(1);
        }
    }
    std::process::exit(0);
}
