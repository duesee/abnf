//! This module contains a collection of all types in the ABNF crate.
//! The types can also be used to manually construct new rules.
//!
//! # Example
//!
//! ```
//! use abnf::types::*;
//!
//! let rule = Rule::new("test", Node::alternatives(&[
//!     Node::rulename("A"),
//!     Node::concatenation(&[
//!         Node::rulename("B"),
//!         Node::rulename("C")
//!     ])
//! ]));
//!
//! println!("{}", rule); // prints "test = A / B C"
//! ```

use std::fmt;

/// Is a rule a basic rule or an incremental alternative?
/// See <https://tools.ietf.org/html/rfc5234#section-3.3>
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
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the definition of the rule. Implemented as a composition of `Node`s.
    pub fn node(&self) -> &Node {
        &self.node
    }

    /// Get the kind of the rule, i.e. `Basic` or `Incremental`.
    pub fn kind(&self) -> Kind {
        self.kind
    }
}

/// A `Node` enumerates all building blocks in ABNF.
/// Any rule is a composition of `Node`s.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Node {
    /// An alternation, e.g. `A / B / C`.
    Alternatives(Vec<Node>),
    /// A concatenation, e.g. `A B C`.
    Concatenation(Vec<Node>),
    /// A repetition, e.g. `*A`.
    Repetition {
        /// How often ...
        repeat: Repeat,
        /// ... is which node repeated?
        node: Box<Node>,
    },
    /// A rulename, i.e. a non-terminal.
    Rulename(String),
    /// A group, e.g. `(A B)`.
    Group(Box<Node>),
    /// An option, e.g. `[A]`.
    Optional(Box<Node>),
    /// A literal text string/terminal, e.g. `"http"`, `%i"hTtP"` or `%s"http"`.
    String(StringLiteral),
    /// A single value within a range (e.g. `%x01-ff`)
    /// or a terminal defined by a series of values (e.g. `%x0f.f1.ce`).
    TerminalValues(TerminalValues),
    /// A prose string, i.e. `<good luck implementing this>`.
    Prose(String),
}

impl Node {
    /// Constructor/Shorthand for Node::Alternatives(...).
    pub fn alternatives(nodes: &[Node]) -> Node {
        Node::Alternatives(nodes.to_vec())
    }

    /// Constructor/Shorthand for Node::Concatenation(...).
    pub fn concatenation(nodes: &[Node]) -> Node {
        Node::Concatenation(nodes.to_vec())
    }

    /// Constructor/Shorthand for Node::Repetition(...).
    pub fn repetition(repeat: Repeat, node: Node) -> Node {
        Node::Repetition {
            repeat,
            node: Box::new(node),
        }
    }

    /// Constructor/Shorthand for Node::Rulename(...).
    pub fn rulename<S: AsRef<str>>(name: S) -> Node {
        Node::Rulename(name.as_ref().to_string())
    }

    /// Constructor/Shorthand for Node::Group(...).
    pub fn group(node: Node) -> Node {
        Node::Group(Box::new(node))
    }

    /// Constructor/Shorthand for Node::Optional(...).
    pub fn optional(node: Node) -> Node {
        Node::Optional(Box::new(node))
    }

    /// Constructor/Shorthand for Node::String(StringLiteral::new(...)).
    pub fn string<S: AsRef<str>>(string: S, case_sensitive: bool) -> Node {
        Node::String(StringLiteral::new(
            string.as_ref().to_owned(),
            case_sensitive,
        ))
    }

    /// Constructor/Shorthand for Node::TerminalValues(...).
    pub fn terminal_values(terminal_values: TerminalValues) -> Node {
        Node::TerminalValues(terminal_values)
    }

    /// Constructor/Shorthand for Node::Prose(...).
    pub fn prose<S: AsRef<str>>(prose: S) -> Node {
        Node::Prose(prose.as_ref().to_string())
    }
}

/// String literal value, either case sensitive or not.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StringLiteral {
    /// String value.
    value: String,
    /// Whether the string is case sensitive or not.
    case_sensitive: bool,
}

impl StringLiteral {
    /// Creates a new string literal.
    pub fn new(string: String, case_sensitive: bool) -> Self {
        Self {
            value: string,
            case_sensitive,
        }
    }

    /// Creates a new case insensitive string literal.
    pub fn case_insensitive(string: String) -> Self {
        Self {
            value: string,
            case_sensitive: false,
        }
    }

    /// Creates a new case sensitive string literal.
    pub fn case_sensitive(string: String) -> Self {
        Self {
            value: string,
            case_sensitive: true,
        }
    }

    /// Returns whether or not the string literal is case sensitive.
    pub fn is_case_sensitive(&self) -> bool {
        self.case_sensitive
    }

    /// Sets whether or not the string literal is case sensitive.
    pub fn set_case_sensitive(&mut self, case_sensitive: bool) {
        self.case_sensitive = case_sensitive
    }

    /// Returns the string content.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Returns the string content.
    ///
    /// Alias for [`value`](Self::value).
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// Returns a mutable reference to the string content.
    pub fn value_mut(&mut self) -> &mut String {
        &mut self.value
    }

    /// Sets the string literal's content.
    pub fn set_value(&mut self, value: String) {
        self.value = value
    }

    /// Turns this string literal into its content.
    pub fn into_value(self) -> String {
        self.value
    }

    /// Turns this string literal into a pair containing its content and a
    /// boolean stating if the string literal is case sensitive or not.
    pub fn into_parts(self) -> (String, bool) {
        (self.value, self.case_sensitive)
    }
}

impl From<String> for StringLiteral {
    /// Converts a `String` into a case insensitive string literal.
    fn from(s: String) -> Self {
        Self::case_insensitive(s)
    }
}

impl fmt::Display for StringLiteral {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.case_sensitive {
            write!(f, "%s\"{}\"", self.value)
        } else {
            write!(f, "\"{}\"", self.value)
        }
    }
}

/// Defines the kind of repetition. This enum is defined in a way,
/// which makes it possible to preserve the parsed variant.
/// As a consequence, multiple logically equivalent forms can be represented,
/// e.g. `4<element> == 4*4<element>`, `*5<element> == 0*5<element>`, etc.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Repeat {
    /// Repeat exactly n times, e.g. `4<element>`.
    Specific(usize),
    /// Repeat with optionally lower and optionally upper bounded value, e.g. `1*3<element>`.
    /// Both bounds are inclusive.
    Variable {
        /// Lower bound (inclusive).
        min: Option<usize>,
        /// Upper bound (inclusive).
        max: Option<usize>,
    },
}

impl Repeat {
    /// Create an unbounded repeat value, i.e. `*`.
    pub fn unbounded() -> Self {
        Self::Variable {
            min: None,
            max: None,
        }
    }

    /// Create a specific repeat value by providing n.
    pub fn specific(n: usize) -> Self {
        Self::Specific(n)
    }

    /// Create a variable repeat value by providing both lower and upper bound.
    pub fn variable(min: Option<usize>, max: Option<usize>) -> Self {
        Self::Variable { min, max }
    }

    /// Get the lower bound.
    pub fn min(&self) -> Option<usize> {
        match *self {
            Self::Specific(n) => Some(n),
            Self::Variable { min, .. } => min,
        }
    }

    /// Get the upper bound.
    pub fn max(&self) -> Option<usize> {
        match *self {
            Self::Specific(n) => Some(n),
            Self::Variable { max, .. } => max,
        }
    }

    /// Get the lower and upper bound as a tuple.
    pub fn min_max(&self) -> (Option<usize>, Option<usize>) {
        (self.min(), self.max())
    }
}

/// Terminal created by numerical values.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TerminalValues {
    // FIXME: Keep base (bin, dec, hex)
    // Relaxed for Unicode support, see <https://github.com/duesee/abnf/pull/3>.
    /// A single value within a range (e.g. `%x01-ff`).
    Range(u32, u32),
    /// A terminal defined by a concatenation of values (e.g. `%x0f.f1.ce`).
    Concatenation(Vec<u32>),
}

impl TerminalValues {
    /// Create an alternation from a lower and upper bound (both inclusive).
    /// See ABNF's "value range alternatives", e.g. `%c##-##`.
    pub fn range(from: u32, to: u32) -> TerminalValues {
        TerminalValues::Range(from, to)
    }

    /// Create a terminal from a series of values.
    /// See ABNF's terminal notation, e.g. `%c##.##.##`.
    pub fn sequence(alts: &[u32]) -> TerminalValues {
        TerminalValues::Concatenation(alts.to_owned())
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
            Node::Alternatives(nodes) => {
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
                match *repeat {
                    Repeat::Specific(n) => {
                        write!(f, "{}", n)?;
                    }
                    Repeat::Variable { min, max } => {
                        if let Some(min) = min {
                            write!(f, "{}", min)?;
                        }

                        write!(f, "*")?;

                        if let Some(max) = max {
                            write!(f, "{}", max)?;
                        }
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
            Node::String(str) => {
                str.fmt(f)?;
            }
            Node::TerminalValues(range) => {
                write!(f, "%x")?;
                match range {
                    TerminalValues::Concatenation(allowed) => {
                        if let Some((last, elements)) = allowed.split_last() {
                            for item in elements {
                                write!(f, "{:02X}.", item)?;
                            }
                            write!(f, "{:02X}", last)?;
                        }
                    }
                    TerminalValues::Range(from, to) => {
                        write!(f, "{:02X}-{:02X}", from, to)?;
                    }
                }
            }
            Node::Prose(str) => {
                write!(f, "<{}>", str)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_rule() {
        let test = Rule::new("rule", Node::rulename("A"));
        let expected = "rule = A";
        let got = test.to_string();
        assert_eq!(expected, got);

        let test = Rule::incremental("rule", Node::rulename("A"));
        let expected = "rule =/ A";
        let got = test.to_string();
        assert_eq!(expected, got);
    }

    #[test]
    fn test_display_prose() {
        let rule = Rule::new("rule", Node::prose("test"));
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
