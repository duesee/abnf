use abnf::abnf::rulelist;

use std::fs::File;
use std::io::{self, Read};

fn read_to_vec(path: &str) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    Ok(data)
}

fn main() -> std::io::Result<()> {
    let paths: Vec<String> = {
        let mut args = std::env::args();
        let _ = args.next(); // skip program name
        args.collect()
    };

    if paths.len() == 0 {
        println!("No files specified. Exit.");
        std::process::exit(1);
    }

    let data = {
        let mut data = Vec::new();
        for path in paths {
            let mut buffer = read_to_vec(&path)?;
            data.append(&mut buffer);
            data.push('\n' as u8);
        }

        data
    };

    let (remaining, rules) = rulelist(&data).unwrap();

    for rule in &rules {
        println!("[!] {}", rule);
        println!("[!] {:#?}\n", rule);
    }

    println!("---------------\n{}", String::from_utf8_lossy(remaining));

    Ok(())
}
