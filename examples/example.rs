use abnf::rulelist;

use std::env::args;
use std::fs::File;
use std::io::Read;

fn main() -> std::io::Result<()> {
    let rules = {
        let mut file = File::open(args().nth(1).expect("no file given"))?;
        let mut data = String::new();
        file.read_to_string(&mut data)?;

        rulelist(&data).unwrap_or_else(|e| {
            println!("{}", e);
            std::process::exit(1);
        })
    };

    for rule in &rules {
        println!("[!] {}", rule);
        println!("[!] {:#?}\n", rule);
    }

    Ok(())
}
