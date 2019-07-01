#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Rule {
    pub name: String,
    pub node: Box<Node>,
}

impl Rule {
    pub fn new(name: &str, node: Node) -> Rule {
        Rule { name: name.into(), node: Box::new(node) }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Node {
    Alternation(Vec<Box<Node>>),
    Concatenation(Vec<Box<Node>>),
    Repetition {
        repeat: Option<Repeat>,
        node: Box<Node>,
    },
    Rulename(String),
    Group(Box<Node>),
    Optional(Box<Node>),
    CharVal(String),
    NumVal(Range),
    ProseVal(String),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Repeat {
    pub min: Option<usize>,
    pub max: Option<usize>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Range {
    OneOf(Vec<u32>), // FIXME: out of spec, but useful?
    Range(u32, u32),
}