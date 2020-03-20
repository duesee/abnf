//! This example shows how to use the `abnf` crate to create a dependency graph of `Rule`s.

use abnf::{
    rulelist,
    types::{Node, Rule},
};
use std::env::args;

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

fn print_gml(rules: Vec<Rule>) {
    println!("graph [");

    for rule in rules.iter() {
        println!(
            "\tnode [id \"{}\" label \"{}\"]",
            rule.get_name(),
            rule.get_name()
        );
    }

    for rule in rules.iter() {
        for dep in rule.calc_dependencies() {
            if ["ALPHA", "BIT", "CHAR", "CR", "CRLF", "CTL", "DIGIT", "DQUOTE", "HEXDIG", "HTAB", "LF", "LWSP", "OCTET", "SP", "VCHAR", "WSP"].contains(&&dep[..]) {
                continue;
            }

            println!("\tedge [source \"{}\" target \"{}\"]", rule.get_name(), dep);
        }
    }

    println!("]");
}

fn print_gv(rules: Vec<Rule>) {
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
}

fn main() -> std::io::Result<()> {
    let rules = {
        let data =
            std::fs::read_to_string(args().nth(1).expect("USAGE: dependencies file [gml|gv]"))?;

        rulelist(&data).unwrap_or_else(|e| {
            println!("{}", e);
            std::process::exit(1);
        })
    };

    let format = args().nth(2).unwrap_or(String::from("gml"));

    match format.as_ref() {
        "gml" => print_gml(rules),
        "gv" => print_gv(rules),
        other => {
            eprintln!("Unknown format \"{}\". Try \"gml\" or \"gv\".", other);
            std::process::exit(1);
        }
    }

    Ok(())
}
