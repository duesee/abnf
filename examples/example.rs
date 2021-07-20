use std::error::Error;

use abnf::rulelist;

fn main() -> Result<(), Box<dyn Error>> {
    let rules = {
        let path = std::env::args().nth(1).ok_or("No path to file given.")?;
        let data = std::fs::read_to_string(path)?;

        rulelist(&data)?
    };

    for rule in &rules {
        println!("// {}", rule);
        println!("{:#?}\n", rule);
    }

    Ok(())
}
