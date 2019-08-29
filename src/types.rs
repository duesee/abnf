use std::fmt;

#[derive(Debug, Clone, Eq, PartialEq)]
/// Is a rule a basic rule or an incremental alternative?
/// See https://tools.ietf.org/html/rfc5234#section-3.3
pub enum Definition {
    /// Basic Rule Definition
    Basic,
    /// Incremental Alternative
    Incremental,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Rule {
    pub name: String,
    pub node: Node,
    pub definition: Definition,
}

impl Rule {
    pub fn new(name: &str, node: Node) -> Rule {
        Rule {
            name: name.into(),
            node: node,
            definition: Definition::Basic,
        }
    }

    pub fn definition(mut self, definition: Definition) -> Self {
        self.definition = definition;
        self
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Node {
    Alternation(Vec<Node>),
    Concatenation(Vec<Node>),
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

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} = {}", self.name, self.node)
    }
}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Node::Alternation(nodes) => {
                if let Some((last, elements)) = nodes.split_last() {
                    for item in elements {
                        write!(f, "{} / ", item)?;
                    }
                    write!(f, "{}", last)?;
                }
            }
            Node::Concatenation(nodes) => {
                if let Some((last, elements)) = nodes.split_last() {
                    for item in elements {
                        write!(f, "{} ", item)?;
                    }
                    write!(f, "{}", last)?;
                }
            }
            Node::Repetition { repeat, node } => {
                if let Some(ref repeat) = repeat {
                    if let Some(min) = repeat.min {
                        write!(f, "{}", min)?;
                    }

                    write!(f, "*")?;

                    if let Some(max) = repeat.max {
                        write!(f, "{}", max)?;
                    }
                }

                write!(f, "{}", node)?;
            }
            Node::Rulename(name) => {
                write!(f, "{}", name)?;
            }
            Node::Group(node) => {
                write!(f, "({})", node)?;
            }
            Node::Optional(node) => {
                write!(f, "[{}]", node)?;
            }
            Node::CharVal(str) => {
                write!(f, "\"{}\"", str)?;
            }
            Node::NumVal(range) => {
                write!(f, "%x")?;
                match range {
                    Range::OneOf(allowed) => {
                        if let Some((last, elements)) = allowed.split_last() {
                            for item in elements {
                                write!(f, "{:02X}.", item)?;
                            }
                            write!(f, "{:02X}", last)?;
                        }
                    }
                    Range::Range(from, to) => {
                        write!(f, "{:02X}-{:02X}", from, to)?;
                    }
                }
            }
            Node::ProseVal(str) => {
                write!(f, "<{}>", str)?;
            }
        }

        Ok(())
    }
}
