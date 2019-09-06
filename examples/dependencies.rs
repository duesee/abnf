//! This example shows how to use the `abnf` crate to create a dependency graph of `Rule`s.

use abnf::{rulelist, Node, Rule};
use std::env::args;
use std::fs::File;
use std::io::Read;

/// A type which implements this trait is able to report on what rules it "depends" on.
/// For simplicity, the dependencies are just a vector of strings here.
trait Dependencies {
    /// Obtain a list of all rulenames.
    fn calc_dependencies(&self) -> Vec<String>;
}

impl Dependencies for Rule {
    fn calc_dependencies(&self) -> Vec<String> {
        self.get_node().calc_dependencies()
    }
}

impl Dependencies for Node {
    fn calc_dependencies(&self) -> Vec<String> {
        match self {
            // If we are an alternation or a concatenation,
            // collect the dependencies of all the alternated/concatenated elements.
            Node::Alternation(nodes) | Node::Concatenation(nodes) => {
                let mut ret_val = Vec::new();
                for node in nodes {
                    for dep in node.calc_dependencies() {
                        if !ret_val.contains(&dep) {
                            ret_val.push(dep);
                        }
                    }
                }
                ret_val
            }
            Node::Group(node) | Node::Optional(node) => node.calc_dependencies(),
            Node::Repetition(repr) => repr.get_node().calc_dependencies(),
            Node::Rulename(name) => vec![name.to_owned()],
            Node::NumVal(_) | Node::CharVal(_) | Node::ProseVal(_) => vec![],
        }
    }
}

fn main() -> std::io::Result<()> {
    let rules = {
        let mut file = File::open(args().nth(1).expect("no file given"))?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;

        let (remaining, rules) = rulelist(&data).expect("error while parsing");

        if !remaining.is_empty() {
            panic!("trailing data");
        }

        rules
    };

    println!("digraph {{");
    println!("\tcompound=true;");
    println!("\toverlap=scalexy;");
    println!("\tsplines=true;");
    println!("\tlayout=neato;\n");
    for rule in rules.iter() {
        let name = rule.get_name().to_owned().replace("-", "_");
        let deps = rule
            .calc_dependencies()
            .iter()
            .map(|name| name.replace("-", "_"))
            .collect::<Vec<_>>();

        println!("\t{} -> {{{}}}", name, deps.join(" "));
    }
    println!("}}");

    Ok(())
}
