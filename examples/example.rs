use abnf::rulelist;

use std::fs::File;
use std::io::{self, Read};

use nom::error::VerboseError;

fn read_to_string(path: &str) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut data = String::new();
    file.read_to_string(&mut data)?;
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
        let mut data = String::new();
        for path in paths {
            let buffer = read_to_string(&path)?;
            data.push_str(&buffer);
            data.push('\n');
        }

        data
    };

    let (remaining, rules) = rulelist::<VerboseError<&str>>(&data).unwrap();

    for rule in &rules {
        println!("[!] {}", rule);
        println!("[!] {:#?}\n", rule);
    }

    println!("---------------\n{}", remaining);

    Ok(())
}
