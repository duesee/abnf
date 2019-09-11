//! This module contains a collection of all types in the ABNF crate.
//! The types can be used to manually construct new rules.
//!
//! **Note**: currently you need to take care of some internals and
//! use specific containers to construct the variants (e.g. `Vec` for an `Alternation` and `String` for a `Rulename`).
//!
//! This crate will provide a better abstraction in the future.
//!
//! # Example
//!
//! ```
//! use abnf::types::*;
//!
//! let rule = Rule::new("test", Node::Alternation(vec![
//!     Node::Rulename("A".into()),
//!     Node::Concatenation(vec![
//!         Node::Rulename("B".into()),
//!         Node::Rulename("C".into())
//!     ])
//! ]));
//!
//! println!("{}", rule); // prints "test = A / B C"
//! ```

use std::fmt;

/// Is a rule a basic rule or an incremental alternative?
/// See https://tools.ietf.org/html/rfc5234#section-3.3
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Kind {
    /// Basic Rule Definition
    Basic,
    /// Incremental Alternative
    Incremental,
}

/// A single ABNF rule with a name, it's definition (implemented as `Node`) and a kind (`Kind::Basic` or `Kind::Incremental`).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Rule {
    name: String,
    node: Node,
    kind: Kind,
}

impl Rule {
    /// Construct a basic rule.
    pub fn new(name: &str, node: Node) -> Rule {
        Rule {
            name: name.into(),
            node,
            kind: Kind::Basic,
        }
    }

    /// Construct an incremental rule.
    pub fn incremental(name: &str, node: Node) -> Rule {
        Rule {
            name: name.into(),
            node,
            kind: Kind::Incremental,
        }
    }

    /// Get the name of the rule.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Get the definition of the rule. Implemented as a composition of `Node`s.
    pub fn get_node(&self) -> &Node {
        &self.node
    }

    /// Get the kind of the rule, i.e. `Basic` or `Incremental`.
    pub fn get_kind(&self) -> Kind {
        self.kind
    }
}

/// A `Node` enumerates all building blocks in ABNF.
/// Any rule is a composition of `Node`s.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Node {
    /// An alternation, e.g. `A / B / C`.
    Alternation(Vec<Node>),
    /// A concatenation, e.g. `A B C`.
    Concatenation(Vec<Node>),
    /// A repetition, e.g. `*A`.
    Repetition(Repetition),
    /// A rulename, i.e. a non-terminal.
    Rulename(String),
    /// A group, e.g. `(A B)`.
    Group(Box<Node>),
    /// An option, e.g. `[A]`.
    Optional(Box<Node>),
    /// A literal text string/terminal, e.g. `"http"`.
    CharVal(String),
    /// A single value within a range (e.g. `%x01-ff`)
    /// or a terminal defined by a series of values (e.g. `%x0f.f1.ce`).
    NumVal(NumVal),
    /// A prose string, i.e. `<good luck implementing this>`.
    ProseVal(String),
}

/// Struct to bind a `Repeat` value to a `Node`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Repetition {
    repeat: Repeat,
    node: Box<Node>,
}

impl Repetition {
    /// Create a Repetition from a repeat value and a node.
    pub fn new(repeat: Repeat, node: Node) -> Self {
        Self {
            repeat,
            node: Box::new(node),
        }
    }

    /// Get the repeat value.
    pub fn get_repeat(&self) -> &Repeat {
        &self.repeat
    }

    /// Get the node which is repeated.
    pub fn get_node(&self) -> &Node {
        &self.node
    }
}

/// An optionally lower and optionally upper bounded repeat value.
/// Both bounds are inclusive.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct Repeat {
    min: Option<usize>,
    max: Option<usize>,
}

impl Repeat {
    /// Create an unbounded repeat value, i.e. `*`.
    pub fn unbounded() -> Self {
        Self {
            min: None,
            max: None,
        }
    }

    /// Create a specific repeat value by providing both lower and upper bound.
    pub fn with(min: Option<usize>, max: Option<usize>) -> Self {
        Self { min, max }
    }

    /// Get the lower bound.
    pub fn get_min(&self) -> Option<usize> {
        self.min
    }

    /// Get the upper bound.
    pub fn get_max(&self) -> Option<usize> {
        self.max
    }

    /// Get the lower and upper bound as a tuple.
    pub fn get_min_max(&self) -> (Option<usize>, Option<usize>) {
        (self.min, self.max)
    }
}

/// A single value within a range (e.g. `%x01-ff`)
/// or a terminal defined by a series of values (e.g. `%x0f.f1.ce`).
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum NumVal {
    Terminal(Vec<u32>),
    Range(u32, u32),
} // FIXME: u32 may be out of spec. But it is useful for UTF-8.

impl NumVal {
    /// Create a terminal from a series of values.
    /// See ABNF's terminal notation, e.g. `%c##.##.##`.
    pub fn terminal(alts: &[u32]) -> NumVal {
        NumVal::Terminal(alts.to_owned())
    }

    /// Create an alternation from a lower and upper bound (both inclusive).
    /// See ABNF's "value range alternatives", e.g. `%c##-##`.
    pub fn range(from: u32, to: u32) -> NumVal {
        NumVal::Range(from, to)
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name)?;
        match self.kind {
            Kind::Basic => write!(f, " = ")?,
            Kind::Incremental => write!(f, " =/ ")?,
        }
        write!(f, "{}", self.node)
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
            Node::Repetition(Repetition { repeat, node }) => {
                if let Some(min) = repeat.min {
                    write!(f, "{}", min)?;
                }

                write!(f, "*")?;

                if let Some(max) = repeat.max {
                    write!(f, "{}", max)?;
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
                    NumVal::Terminal(allowed) => {
                        if let Some((last, elements)) = allowed.split_last() {
                            for item in elements {
                                write!(f, "{:02X}.", item)?;
                            }
                            write!(f, "{:02X}", last)?;
                        }
                    }
                    NumVal::Range(from, to) => {
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_display_rule() {
        let test = Rule::new("rule", Node::Rulename("A".into()));
        let expected = "rule = A";
        let got = test.to_string();
        assert_eq!(expected, got);

        let test =
            Rule::incremental("rule", Node::Rulename("A".into()));
        let expected = "rule =/ A";
        let got = test.to_string();
        assert_eq!(expected, got);
    }

    #[test]
    fn test_display_prose() {
        let rule = Rule::new("rule", Node::ProseVal("test".into()));
        assert_eq!("rule = <test>", rule.to_string());
    }

    #[test]
    fn test_impl_trait() {
        // Make sure that others can implement their own traits for Rule.
        trait Foo {
            fn foo(&self);
        }

        impl Foo for Rule {
            fn foo(&self) {
                println!("{}", self.name);
            }
        }
    }
}
