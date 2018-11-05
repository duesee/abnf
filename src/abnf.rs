#![allow(non_snake_case)]

use super::core::*;

use nom::{Context, Err, ErrorKind, IResult, Needed};
use std::fmt;

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} = {}", self.name, self.elements)
    }
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
                write!(f, "{:?}", range)?;
            }
            ProseVal(val) => {
                write!(f, "<{}>", val)?;
            }
        }
        Ok(())
    }
}

impl fmt::Display for Group {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({})", self.alternation)
    }
}

impl fmt::Display for Optional {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[{}]", self.alternation)
    }
}

#[derive(Debug)]
pub struct Rule {
    pub name: String,
    pub elements: Alternation,
}

#[derive(Debug)]
pub struct Alternation {
    pub concatenations: Vec<Concatenation>,
}

#[derive(Debug)]
pub struct Concatenation {
    pub repetitions: Vec<Repetition>,
}

#[derive(Debug)]
pub struct Repetition {
    pub repeat: Option<Repeat>,
    pub element: Element,
}

#[derive(Debug)]
pub struct Repeat {
    pub min: Option<usize>,
    pub max: Option<usize>,
}

#[derive(Debug)]
pub enum Element {
    Rulename(String),
    Group(Group),
    Option(Optional),
    CharVal(String),
    NumVal(Range),
    ProseVal(String),
}

#[derive(Debug)]
pub struct Group {
    pub alternation: Alternation,
}

#[derive(Debug)]
pub struct Optional {
    pub alternation: Alternation
}

#[derive(Debug, Eq, PartialEq)]
pub enum Range {
    OneOf(Vec<u8>),
    Range(u8, u8),
}

/// rulelist = 1*( rule / (*WSP c-nl) )
named!(pub rulelist_comp<Vec<Rule>>, do_parse!(
    all: many1!(
        complete!(alt!(
            map!(rule, |rule| Some(rule)) |
            map!(tuple!(many0!(WSP), c_nl), |_| None)
        ))
    ) >> ({
        let mut res = vec![];
        for item in all.into_iter() {
            if let Some(rule) = item {
                res.push(rule)
            }
        }
        res
    })
));

/// rule = rulename defined-as elements c-nl
///         ; continues if next line starts
///         ;  with white space
named!(pub rule<Rule>, do_parse!(
    name: rulename >>
    defined_as >>
    elements: elements >>
    c_nl >> (
        Rule {
            name,
            elements,
        }
    )
));

/// rulename = ALPHA *(ALPHA / DIGIT / "-")
named!(pub rulename<String>, do_parse!(
    head: ALPHA >>
    tail: many0!(
        alt!(
            ALPHA |
            DIGIT |
            char!('-')
        )
    ) >> ({
        let mut name = vec![head];
        name.extend(tail);
        name.into_iter().collect::<String>()
    })
));

/// defined-as = *c-wsp ("=" / "=/") *c-wsp
///               ; basic rules definition and
///               ;  incremental alternatives
named!(pub defined_as<()>, do_parse!(
    many0!(c_wsp) >>
    alt!(tag!("=/") | tag!("=")) >>
    many0!(c_wsp) >> (
        ()
    )
));

/// elements = alternation *WSP
named!(pub elements<Alternation>, do_parse!(
    alternation: alternation >>
    many0!(WSP) >> (
        alternation
    )
));

/// c-wsp = WSP / (c-nl WSP)
named!(pub c_wsp<()>, do_parse!(
    alt!(
        map!(tuple!(c_nl, WSP), |_| ()) |
        map!(WSP, |_| ())
    ) >> (

    )
));

/// c-nl = comment / CRLF
///         ; comment or newline
named!(pub c_nl<()>, do_parse!(
    alt!(
        comment |
        map!(CRLF, |_| ())
    ) >> (

    )
));

/// comment = ";" *(WSP / VCHAR) CRLF
named!(pub comment<()>, do_parse!(
    char!(';') >>
    many0!(
        alt!(
            WSP |
            VCHAR
        )
    ) >>
    CRLF >> (

    )
));

/// alternation = concatenation *(*c-wsp "/" *c-wsp concatenation)
named!(pub alternation<Alternation>, do_parse!(
    concatenations: separated_list!(
        tuple!(many0!(c_wsp), char!('/'), many0!(c_wsp)),
        concatenation
    ) >> (
        Alternation {
            concatenations
        }
    )
));

// concatenation = repetition *(1*c-wsp repetition)
named!(pub concatenation<Concatenation>, do_parse!(
    repetitions: separated_list!(many0!(c_wsp), repetition) >> (
        Concatenation {
            repetitions
        }
    )
));

/// repetition = [repeat] element
named!(pub repetition<Repetition>, do_parse!(
    repeat: opt!(repeat) >>
    element: element >> (
        Repetition {
            repeat,
            element,
        }
    )
));

/// repeat = 1*DIGIT / (*DIGIT "*" *DIGIT)
named!(pub repeat<Repeat>, do_parse!(
    val: alt!(
        map!(tuple!(many0!(DIGIT), char!('*'), many0!(DIGIT)), |(min, _, max)| {
            let min = if min.len() > 0 {
                Some(usize::from_str_radix(&min.into_iter().collect::<String>(), 10).unwrap())
            } else {
                None
            };

            let max = if max.len() > 0 {
                Some(usize::from_str_radix(&max.into_iter().collect::<String>(), 10).unwrap())
            } else {
                None
            };

            Repeat { min, max }
        }) |
        map!(many1!(DIGIT), |min| {
            let min = usize::from_str_radix(&min.into_iter().collect::<String>(), 10).unwrap();
            Repeat { min: Some(min), max: Some(min) }
        })
    ) >> (
        val
    )
));

/// element = rulename / group / option / char-val / num-val / prose-val
named!(pub element<Element>, do_parse!(
    element: alt!(
        map!(rulename,  |e| Element::Rulename(e)) |
        map!(group,     |e| Element::Group(e)) |
        map!(option,    |e| Element::Option(e)) |
        map!(char_val,  |e| Element::CharVal(e)) |
        map!(num_val,   |e| Element::NumVal(e)) |
        map!(prose_val, |e| Element::ProseVal(e))
    ) >> (
        element
    )
));

/// group = "(" *c-wsp alternation *c-wsp ")"
named!(pub group<Group>, do_parse!(
    char!('(') >>
    many0!(c_wsp) >>
    alternation: alternation >>
    many0!(c_wsp) >>
    char!(')') >> (
        Group {
            alternation
        }
    )
));

/// option = "[" *c-wsp alternation *c-wsp "]"
named!(pub option<Optional>, do_parse!(
    char!('[') >> 
    many0!(c_wsp) >>
    alternation: alternation >>
    many0!(c_wsp) >>
    char!(']') >> (
        Optional {
            alternation
        }
    )
));

/// char-val = DQUOTE *(%x20-21 / %x23-7E) DQUOTE
///             ; quoted string of SP and VCHAR
///             ;  without DQUOTE
named!(pub char_val<String>, do_parse!(
    DQUOTE >>
    val: many0!(CHAR_VAL_CHARS) >>
    DQUOTE >> (
        val.into_iter().collect()
    )
));

/// num-val = "%" (bin-val / dec-val / hex-val)
named!(pub num_val<Range>, do_parse!(
    char!('%') >>
    range: alt!(
        bin_val |
        dec_val |
        hex_val
    ) >> (
        range
    )
));

/// bin-val = "b" 1*BIT [ 1*("." 1*BIT) / ("-" 1*BIT) ]
///            ; series of concatenated bit values
///            ;  or single ONEOF range
named!(pub bin_val<Range>, do_parse!(
    char!('b') >>
    start: map!(many1!(BIT), |val| {
        u8::from_str_radix(&val.into_iter().collect::<String>(), 2).expect("should never happen")
    }) >>
    compl: opt!(
        alt!(
            map!(many1!(tuple!(char!('.'), many1!(BIT))), |pairs| {
                let mut all = vec![start];
                for (_, val) in pairs.into_iter() {
                    all.push(u8::from_str_radix(&val.into_iter().collect::<String>(), 2).expect("should never happen"))
                }
                Range::OneOf(all)
            }) |
            map!(tuple!(char!('-'), many1!(BIT)), |(_, end)| {
                Range::Range(start, u8::from_str_radix(&end.into_iter().collect::<String>(), 2).expect("should never happen"))
            })
        )
    ) >> (
        if let Some(r) = compl {
            r
        } else {
            Range::OneOf(vec![start])
        }
    )
));

/// dec-val = "d" 1*DIGIT [ 1*("." 1*DIGIT) / ("-" 1*DIGIT) ]
named!(pub dec_val<Range>, do_parse!(
    char!('d') >>
    start: map!(many1!(DIGIT), |val| {
        u8::from_str_radix(&val.into_iter().collect::<String>(), 10).unwrap()
    }) >>
    compl: opt!(
        alt!(
            map!(many1!(tuple!(char!('.'), many1!(DIGIT))), |pairs| {
                let mut all = vec![start];
                for (_, val) in pairs.into_iter() {
                    all.push(u8::from_str_radix(&val.into_iter().collect::<String>(), 10).unwrap())
                }
                Range::OneOf(all)
            }) |
            map!(tuple!(char!('-'), many1!(DIGIT)), |(_, end)| {
                Range::Range(start, u8::from_str_radix(&end.into_iter().collect::<String>(), 10).unwrap())
            })
        )
    ) >> (
        if let Some(r) = compl {
            r
        } else {
            Range::OneOf(vec![start])
        }
    )
));

/// hex-val = "x" 1*HEXDIG [ 1*("." 1*HEXDIG) / ("-" 1*HEXDIG) ]
named!(pub hex_val<Range>, do_parse!(
    char!('x') >>
    start: map!(many1!(HEXDIG), |val| {
        u8::from_str_radix(&val.into_iter().collect::<String>(), 16).unwrap()
    }) >>
    compl: opt!(
        alt!(
            map!(many1!(tuple!(char!('.'), many1!(HEXDIG))), |pairs| {
                let mut all = vec![start];
                for (_, val) in pairs.into_iter() {
                    all.push(u8::from_str_radix(&val.into_iter().collect::<String>(), 16).unwrap())
                }
                Range::OneOf(all)
            }) |
            map!(tuple!(char!('-'), many1!(HEXDIG)), |(_, end)| {
                Range::Range(start, u8::from_str_radix(&end.into_iter().collect::<String>(), 16).unwrap())
            })
        )
    ) >> (
        if let Some(r) = compl {
            r
        } else {
            Range::OneOf(vec![start])
        }
    )
));

/// prose-val = "<" *(%x20-3D / %x3F-7E) ">"
///              ; bracketed string of SP and VCHAR without angles
///              ; prose description, to be used as last resort
named!(pub prose_val<String>, do_parse!(
    char!('<') >> 
    val: many0!(PROSE_VAL_CHARS) >>
    char!('>') >> (
        val.into_iter().collect()
    )
));

fn CHAR_VAL_CHARS(i:&[u8]) -> IResult<&[u8], char> {
    if i.len() < 1 {
        Err(Err::Incomplete(Needed::Size(1)))
    } else {
        match i[0] {
            0x20 ..= 0x21 | 0x23 ..= 0x7E => {
                Ok((&i[1..], i[0] as char))
            }
            _ => {
                let e:ErrorKind<u32> = ErrorKind::Tag;
                Err(Err::Error(Context::Code(i, e)))
            }
        }
    }
}

fn PROSE_VAL_CHARS(i:&[u8]) -> IResult<&[u8], char> {
    if i.len() < 1 {
        Err(Err::Incomplete(Needed::Size(1)))
    } else {
        match i[0] {
            0x20 ..= 0x3D | 0x3F ..= 0x7E => {
                Ok((&i[1..], i[0] as char))
            }
            _ => {
                let e:ErrorKind<u32> = ErrorKind::Tag;
                Err(Err::Error(Context::Code(i, e)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_num_val() {
        let expected = Range::OneOf(vec![0x00, 0x0A, 0xff]);
        let got1 = num_val(b"%b0.1010.11111111?");
        let got2 = num_val(b"%d0.10.255?");
        let got3 = num_val(b"%x0.A.ff?");
        assert_eq!(expected, got1.unwrap().1);
        assert_eq!(expected, got2.unwrap().1);
        assert_eq!(expected, got3.unwrap().1);
    }

    #[test]
    fn test_bin_val() {
        let expected = Range::OneOf(vec![0x00, 0x03, 0xff]);
        let got = bin_val(b"b00.11.11111111?");
        assert_eq!(expected, got.unwrap().1);

        let expected = Range::Range(0, 255);
        let got = bin_val(b"b00-11111111?");
        assert_eq!(expected, got.unwrap().1)
    }

    #[test]
    fn test_dec_val() {
        let expected = Range::OneOf(vec![0, 42, 255]);
        let got = dec_val(b"d0.42.255?");
        assert_eq!(expected, got.unwrap().1);

        let expected = Range::Range(0, 255);
        let got = dec_val(b"d0-255?");
        assert_eq!(expected, got.unwrap().1)
    }

    #[test]
    fn test_hex_val() {
        let expected = Range::OneOf(vec![0xCA, 0xFF, 0xEE]);
        let got = hex_val(b"xCA.FF.EE?");
        assert_eq!(expected, got.unwrap().1);

        let expected = Range::Range(0, 255);
        let got = hex_val(b"x00-FF?");
        assert_eq!(expected, got.unwrap().1)
    }

    #[test]
    fn test_prose_val() {
        assert_eq!("Hello, World!", prose_val(b"<Hello, World!>").unwrap().1)
    }
}
