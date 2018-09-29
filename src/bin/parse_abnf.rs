extern crate abnf;

use std::fs::File;
use std::io::{self, Read};

use abnf::abnf::rulelist_comp;

fn read_to_vec(path: &str) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    Ok(data)
}

fn main() {
    // The files contain an extra newline at the end,
    // so that they can be easily concatenated.
    let mut data = read_to_vec("assets/abnf_core.abnf").unwrap();
    let mut abnf = read_to_vec("assets/abnf.abnf").unwrap();
    let mut smtp = read_to_vec("assets/smtp.abnf").unwrap();
    let mut imap = read_to_vec("assets/imap4rev1.abnf").unwrap();

    data.append(&mut abnf);
    data.append(&mut smtp);
    data.append(&mut imap);

    // nom is a streaming parser. Thus, when handling finite input,
    // use functions with _comp suffix to avoid `Err::Incomplete`.
    let res = rulelist_comp(&data).unwrap().1;

    for rule in &res {
        println!("{}\n", rule);
    }
}
