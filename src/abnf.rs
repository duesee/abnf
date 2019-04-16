#![allow(non_snake_case)]

//!
//! Parsing of ABNF
//!
//! See https://tools.ietf.org/html/rfc5234#section-4
//!

//
// TODO: can we replace nom's
//   named_attr!(#[doc = ""], ...
// with something less distracting? We should document public functions,
// but currently nom's syntax is really hard to read in the source code.
//

use super::core::*;

use nom::{Context, Err, ErrorKind, IResult, Needed};
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
    pub alternation: Alternation
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

named_attr!(#[doc = r#"
```text
rulelist = 1*( rule / (*WSP c-nl) )
```
"#], pub rulelist_comp<Vec<Rule>>, do_parse!(
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

named_attr!(#[doc = r#"
```text
rule = rulename defined-as elements c-nl
        ; continues if next line starts
        ;  with white space
```
"#], pub rule<Rule>, do_parse!(
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

named_attr!(#[doc = r#"
```text
rulename = ALPHA *(ALPHA / DIGIT / "-")
```
"#], pub rulename<String>, do_parse!(
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

named_attr!(#[doc = r#"
```text
defined-as = *c-wsp ("=" / "=/") *c-wsp
              ; basic rules definition and
              ;  incremental alternatives
```
"#], pub defined_as<()>, do_parse!(
    many0!(c_wsp) >>
    alt!(tag!("=/") | tag!("=")) >>
    many0!(c_wsp) >> (
        ()
    )
));

named_attr!(#[doc = r#"
```text
elements = alternation *WSP
```
"#], pub elements<Alternation>, do_parse!(
    alternation: alternation >>
    many0!(WSP) >> (
        alternation
    )
));

named_attr!(#[doc = r#"
```text
c-wsp = WSP / (c-nl WSP)
```
"#], pub c_wsp<()>, do_parse!(
    alt!(
        map!(tuple!(c_nl, WSP), |_| ()) |
        map!(WSP, |_| ())
    ) >> (

    )
));

named_attr!(#[doc = r#"
```text
c-nl = comment / CRLF
        ; comment or newline
```
"#], pub c_nl<()>, do_parse!(
    alt!(
        comment |
        map!(CRLF, |_| ())
    ) >> (

    )
));

named_attr!(#[doc = r#"
```text
comment = ";" *(WSP / VCHAR) CRLF
```
"#], pub comment<()>, do_parse!(
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

named_attr!(#[doc = r#"
```text
alternation = concatenation *(*c-wsp "/" *c-wsp concatenation)
```
"#], pub alternation<Alternation>, do_parse!(
    concatenations: separated_list!(
        tuple!(many0!(c_wsp), char!('/'), many0!(c_wsp)),
        concatenation
    ) >> (
        Alternation {
            concatenations
        }
    )
));

named_attr!(#[doc = r#"
```text
concatenation = repetition *(1*c-wsp repetition)
```
"#], pub concatenation<Concatenation>, do_parse!(
    repetitions: separated_list!(many0!(c_wsp), repetition) >> (
        Concatenation {
            repetitions
        }
    )
));

named_attr!(#[doc = r#"
```text
repetition = [repeat] element
```
"#], pub repetition<Repetition>, do_parse!(
    repeat: opt!(repeat) >>
    element: element >> (
        Repetition {
            repeat,
            element,
        }
    )
));

named_attr!(#[doc = r#"
```text
repeat = 1*DIGIT / (*DIGIT "*" *DIGIT)
```
"#], pub repeat<Repeat>, do_parse!(
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

named_attr!(#[doc = r#"
```text
element = rulename / group / option / char-val / num-val / prose-val
```
"#], pub element<Element>, do_parse!(
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

named_attr!(#[doc = r#"
```text
group = "(" *c-wsp alternation *c-wsp ")"
```
"#], pub group<Group>, do_parse!(
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

named_attr!(#[doc = r#"
```text
option = "[" *c-wsp alternation *c-wsp "]"
```
"#], pub option<Optional>, do_parse!(
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

named_attr!(#[doc = r#"
```text
char-val = DQUOTE *(%x20-21 / %x23-7E) DQUOTE
            ; quoted string of SP and VCHAR
            ;  without DQUOTE
```
"#], pub char_val<String>, do_parse!(
    DQUOTE >>
    val: many0!(CHAR_VAL_CHARS) >>
    DQUOTE >> (
        val.into_iter().collect()
    )
));

named_attr!(#[doc = r#"
```text
num-val = "%" (bin-val / dec-val / hex-val)
```
"#], pub num_val<Range>, do_parse!(
    char!('%') >>
    range: alt!(
        bin_val |
        dec_val |
        hex_val
    ) >> (
        range
    )
));

named_attr!(#[doc = r#"
```text
bin-val = "b" 1*BIT [ 1*("." 1*BIT) / ("-" 1*BIT) ]
           ; series of concatenated bit values
           ;  or single ONEOF range
```
"#], pub bin_val<Range>, do_parse!(
    char!('b') >>
    start: map!(many1!(BIT), |val| {
        u32::from_str_radix(&val.into_iter().collect::<String>(), 2).expect("should never happen")
    }) >>
    compl: opt!(
        alt!(
            map!(many1!(tuple!(char!('.'), many1!(BIT))), |pairs| {
                let mut all = vec![start];
                for (_, val) in pairs.into_iter() {
                    all.push(u32::from_str_radix(&val.into_iter().collect::<String>(), 2).expect("should never happen"))
                }
                Range::OneOf(all)
            }) |
            map!(tuple!(char!('-'), many1!(BIT)), |(_, end)| {
                Range::Range(start, u32::from_str_radix(&end.into_iter().collect::<String>(), 2).expect("should never happen"))
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

named_attr!(#[doc = r#"
```text
dec-val = "d" 1*DIGIT [ 1*("." 1*DIGIT) / ("-" 1*DIGIT) ]
```
"#], pub dec_val<Range>, do_parse!(
    char!('d') >>
    start: map!(many1!(DIGIT), |val| {
        u32::from_str_radix(&val.into_iter().collect::<String>(), 10).unwrap()
    }) >>
    compl: opt!(
        alt!(
            map!(many1!(tuple!(char!('.'), many1!(DIGIT))), |pairs| {
                let mut all = vec![start];
                for (_, val) in pairs.into_iter() {
                    all.push(u32::from_str_radix(&val.into_iter().collect::<String>(), 10).unwrap())
                }
                Range::OneOf(all)
            }) |
            map!(tuple!(char!('-'), many1!(DIGIT)), |(_, end)| {
                Range::Range(start, u32::from_str_radix(&end.into_iter().collect::<String>(), 10).unwrap())
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

named_attr!(#[doc = r#"
```text
hex-val = "x" 1*HEXDIG [ 1*("." 1*HEXDIG) / ("-" 1*HEXDIG) ]
```
"#], pub hex_val<Range>, do_parse!(
    char!('x') >>
    start: map!(many1!(HEXDIG), |val| {
        u32::from_str_radix(&val.into_iter().collect::<String>(), 16).unwrap()
    }) >>
    compl: opt!(
        alt!(
            map!(many1!(tuple!(char!('.'), many1!(HEXDIG))), |pairs| {
                let mut all = vec![start];
                for (_, val) in pairs.into_iter() {
                    all.push(u32::from_str_radix(&val.into_iter().collect::<String>(), 16).unwrap())
                }
                Range::OneOf(all)
            }) |
            map!(tuple!(char!('-'), many1!(HEXDIG)), |(_, end)| {
                Range::Range(start, u32::from_str_radix(&end.into_iter().collect::<String>(), 16).unwrap())
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

named_attr!(#[doc = r#"
```text
prose-val = "<" *(%x20-3D / %x3F- E) ">"
             ; bracketed string of SP and VCHAR without angles
             ; prose description, to be used as last resort
```
"#], pub prose_val<String>, do_parse!(
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
