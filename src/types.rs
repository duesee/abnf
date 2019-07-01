use std::fmt;

#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub elements: Alternation,
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} = {}", self.name, self.elements)
    }
}

#[derive(Debug, Clone)]
pub struct Alternation {
    pub concatenations: Vec<Concatenation>,
}

impl fmt::Display for Alternation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some((last, elements)) = self.concatenations.split_last() {
            for item in elements {
                write!(f, "{} / ", item)?;
            }
            write!(f, "{}", last)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Concatenation {
    pub repetitions: Vec<Repetition>,
}

impl fmt::Display for Concatenation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some((last, elements)) = self.repetitions.split_last() {
            for item in elements {
                write!(f, "{} ", item)?;
            }
            write!(f, "{}", last)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Repetition {
    pub repeat: Option<Repeat>,
    pub element: Element,
}

impl fmt::Display for Repetition {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(ref repeat) = self.repeat {
            if let Some(min) = repeat.min {
                write!(f, "{}", min)?;
            }

            write!(f, "*")?;

            if let Some(max) = repeat.max {
                write!(f, "{}", max)?;
            }
        }

        write!(f, "{}", self.element)
    }
}

#[derive(Debug, Clone)]
pub struct Repeat {
    pub min: Option<usize>,
    pub max: Option<usize>,
}

#[derive(Debug, Clone)]
pub enum Element {
    Rulename(String),
    Group(Group),
    Option(Optional),
    CharVal(String),
    NumVal(Range),
    ProseVal(String),
}

impl fmt::Display for Element {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Element::*;

        match self {
            Rulename(name) => {
                write!(f, "{}", name)?;
            }
            Group(group) => {
                write!(f, "{}", group)?;
            }
            Option(option) => {
                write!(f, "{}", option)?;
            }
            CharVal(val) => {
                write!(f, "\"{}\"", val)?;
            }
            NumVal(range) => {
                write!(f, "{}", range)?;
            }
            ProseVal(val) => {
                write!(f, "<{}>", val)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Group {
    pub alternation: Alternation,
}

impl fmt::Display for Group {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({})", self.alternation)
    }
}

#[derive(Debug, Clone)]
pub struct Optional {
    pub alternation: Alternation,
}

impl fmt::Display for Optional {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[{}]", self.alternation)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Range {
    OneOf(Vec<u32>),
    Range(u32, u32),
}

impl fmt::Display for Range {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "%x")?;
        match self {
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
        Ok(())
    }
}