#![allow(non_snake_case)]

//!
//! Parsing of ABNF
//!
//! See https://tools.ietf.org/html/rfc5234#section-4
//!

use super::core::*;
use super::types::*;

use nom::branch::alt;
use nom::bytes::complete::{tag, take_while};
use nom::character::complete::char;
use nom::combinator::{map, opt};
use nom::multi::{many0, many1};
use nom::sequence::tuple;
use nom::IResult;

/// Errata ID: 3076
/// rulelist = 1*( rule / (*WSP c-nl) )
pub fn rulelist(input: &[u8]) -> IResult<&[u8], Vec<Rule>> {
    let parser = many1(alt((
        map(rule, |rule| Some(rule)),
        map(tuple((many0(WSP), c_nl)), |_| None),
    )));

    let (input, rulelist) = parser(input)?;

    let mut res = vec![];
    for rule in rulelist.into_iter() {
        if let Some(rule) = rule {
            res.push(rule)
        }
    }

    Ok((input, res))
}

/// rule = rulename defined-as elements c-nl
///         ; continues if next line starts
///         ;  with white space
pub fn rule(input: &[u8]) -> IResult<&[u8], Rule> {
    let parser = tuple((rulename, defined_as, elements, c_nl));

    let (input, (name, _, elements, _)) = parser(input)?;

    Ok((input, Rule::new(&name, elements)))
}

/// rulename = ALPHA *(ALPHA / DIGIT / "-")
pub fn rulename(input: &[u8]) -> IResult<&[u8], String> {
    let valid = |x| is_ALPHA(x) || is_DIGIT(x) || x == '-' as u8;

    let (input, (head, tail)) = tuple((ALPHA, take_while(valid)))(input)?;

    let mut val = vec![head as u8];
    val.extend(tail.iter());

    Ok((input, val.into_iter().map(|x| x as char).collect()))
}

/// defined-as = *c-wsp ("=" / "=/") *c-wsp
///               ; basic rules definition and
///               ;  incremental alternatives
pub fn defined_as(input: &[u8]) -> IResult<&[u8], ()> {
    let parser = tuple((many0(c_wsp), alt((tag("=/"), tag("="))), many0(c_wsp)));

    let (input, _) = parser(input)?;

    Ok((input, ()))
}

/// Errata ID: 2968
/// elements = alternation *WSP
pub fn elements(input: &[u8]) -> IResult<&[u8], Node> {
    let parser = tuple((alternation, many0(WSP)));

    let (input, (alternation, _)) = parser(input)?;

    Ok((input, alternation))
}

///c-wsp = WSP / (c-nl WSP)
pub fn c_wsp(input: &[u8]) -> IResult<&[u8], ()> {
    let parser = alt((map(WSP, |_| ()), map(tuple((c_nl, WSP)), |_| ())));

    let (input, _) = parser(input)?;

    Ok((input, ()))
}

/// c-nl = comment / CRLF ; comment or newline
pub fn c_nl(input: &[u8]) -> IResult<&[u8], ()> {
    let parser = alt((comment, map(CRLF, |_| ())));

    let (input, _) = parser(input)?;

    Ok((input, ()))
}

/// comment = ";" *(WSP / VCHAR) CRLF
pub fn comment(input: &[u8]) -> IResult<&[u8], ()> {
    let valid = |x| is_WSP(x) || is_VCHAR(x);

    let (input, (_, _, _)) = tuple((char(';'), take_while(valid), CRLF))(input)?;

    Ok((input, ()))
}

/// alternation = concatenation *(*c-wsp "/" *c-wsp concatenation)
pub fn alternation(input: &[u8]) -> IResult<&[u8], Node> {
    let parser = tuple((
        concatenation,
        many0(tuple((
            many0(c_wsp),
            char('/'),
            many0(c_wsp),
            concatenation,
        ))),
    ));

    let (input, (head, tail)) = parser(input)?;

    let mut concatenations = vec![Box::new(head)];

    for (_, _, _, item) in tail {
        concatenations.push(Box::new(item))
    }

    // if alternation has only one child, do not wrap it in a `Node::Alternation`.
    if concatenations.len() == 1 {
        Ok((input, *concatenations.pop().unwrap()))
    } else {
        Ok((input, Node::Alternation(concatenations)))
    }
}

/// concatenation = repetition *(1*c-wsp repetition)
pub fn concatenation(input: &[u8]) -> IResult<&[u8], Node> {
    let parser = tuple((repetition, many0(tuple((many1(c_wsp), repetition)))));

    let (input, (head, tail)) = parser(input)?;

    let mut repetitions = vec![Box::new(head)];

    for (_, item) in tail {
        repetitions.push(Box::new(item))
    }

    // if concatenation has only one child, do not wrap it in a `Node::Concatenation`.
    if repetitions.len() == 1 {
        Ok((input, *repetitions.pop().unwrap()))
    } else {
        Ok((input, Node::Concatenation(repetitions)))
    }
}

/// repetition = [repeat] element
pub fn repetition(input: &[u8]) -> IResult<&[u8], Node> {
    let parser = tuple((opt(repeat), element));

    let (input, (repeat, node)) = parser(input)?;

    // if there is no repeat, do not wrap it in a `Node::Repetition`.
    if repeat.is_some() {
        Ok((
            input,
            Node::Repetition {
                repeat: repeat,
                node: Box::new(node),
            },
        ))
    } else {
        Ok((input, node))
    }
}

/// repeat = 1*DIGIT / (*DIGIT "*" *DIGIT)
pub fn repeat(input: &[u8]) -> IResult<&[u8], Repeat> {
    let parser = alt((
        map(
            tuple((many0(DIGIT), char('*'), many0(DIGIT))),
            |(min, _, max)| {
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
            },
        ),
        map(many1(DIGIT), |min| {
            let min = usize::from_str_radix(&min.into_iter().collect::<String>(), 10).unwrap();
            Repeat {
                min: Some(min),
                max: Some(min),
            }
        }),
    ));

    let (input, repeat) = parser(input)?;

    Ok((input, repeat))
}

/// element = rulename / group / option / char-val / num-val / prose-val
pub fn element(input: &[u8]) -> IResult<&[u8], Node> {
    let parser = alt((
        map(rulename, |e| Node::Rulename(e)),
        map(group, |e| e),
        map(option, |e| e),
        map(char_val, |e| Node::CharVal(e)),
        map(num_val, |e| Node::NumVal(e)),
        map(prose_val, |e| Node::ProseVal(e)),
    ));

    let (input, val) = parser(input)?;

    Ok((input, val))
}

/// group = "(" *c-wsp alternation *c-wsp ")"
pub fn group(input: &[u8]) -> IResult<&[u8], Node> {
    let parser = tuple((
        char('('),
        many0(c_wsp),
        alternation,
        many0(c_wsp),
        char(')'),
    ));

    let (input, (_, _, alternation, _, _)) = parser(input)?;

    Ok((input, Node::Group(Box::new(alternation))))
}

/// option = "[" *c-wsp alternation *c-wsp "]"
pub fn option(input: &[u8]) -> IResult<&[u8], Node> {
    let parser = tuple((
        char('['),
        many0(c_wsp),
        alternation,
        many0(c_wsp),
        char(']'),
    ));

    let (input, (_, _, alternation, _, _)) = parser(input)?;

    Ok((input, Node::Optional(Box::new(alternation))))
}

/// char-val = DQUOTE *(%x20-21 / %x23-7E) DQUOTE
///             ; quoted string of SP and VCHAR
///             ;  without DQUOTE
pub fn char_val(input: &[u8]) -> IResult<&[u8], String> {
    let char_val_chars = |x| match x {
        0x20..=0x21 | 0x23..=0x7E => true,
        _ => false,
    };

    let (input, (_, val, _)) = tuple((DQUOTE, take_while(char_val_chars), DQUOTE))(input)?;

    Ok((input, val.into_iter().map(|b| *b as char).collect()))
}

/// num-val = "%" (bin-val / dec-val / hex-val)
pub fn num_val(input: &[u8]) -> IResult<&[u8], Range> {
    let parser = tuple((char('%'), alt((bin_val, dec_val, hex_val))));

    let (input, (_, range)) = parser(input)?;

    Ok((input, range))
}

/// bin-val = "b" 1*BIT [ 1*("." 1*BIT) / ("-" 1*BIT) ]
///            ; series of concatenated bit values
///            ;  or single ONEOF range
pub fn bin_val(input: &[u8]) -> IResult<&[u8], Range> {
    let (input, _) = char('b')(input)?;

    let (input, start) = map(many1(BIT), |val| {
        u32::from_str_radix(&val.into_iter().collect::<String>(), 2).expect("should never happen")
    })(input)?;

    let (input, compl) = opt(alt((
        map(many1(tuple((char('.'), many1(BIT)))), |pairs| {
            let mut all = vec![start];
            for (_, val) in pairs.into_iter() {
                all.push(
                    u32::from_str_radix(&val.into_iter().collect::<String>(), 2)
                        .expect("should never happen"),
                )
            }
            Range::OneOf(all)
        }),
        map(tuple((char('-'), many1(BIT))), |(_, end)| {
            Range::Range(
                start,
                u32::from_str_radix(&end.into_iter().collect::<String>(), 2)
                    .expect("should never happen"),
            )
        }),
    )))(input)?;

    if let Some(r) = compl {
        Ok((input, r))
    } else {
        Ok((input, Range::OneOf(vec![start])))
    }
}

/// dec-val = "d" 1*DIGIT [ 1*("." 1*DIGIT) / ("-" 1*DIGIT) ]
pub fn dec_val(input: &[u8]) -> IResult<&[u8], Range> {
    let (input, _) = char('d')(input)?;

    let (input, start) = map(many1(DIGIT), |val| {
        u32::from_str_radix(&val.into_iter().collect::<String>(), 10).unwrap()
    })(input)?;

    let (input, compl) = opt(alt((
        map(many1(tuple((char('.'), many1(DIGIT)))), |pairs| {
            let mut all = vec![start];
            for (_, val) in pairs.into_iter() {
                all.push(u32::from_str_radix(&val.into_iter().collect::<String>(), 10).unwrap())
            }
            Range::OneOf(all)
        }),
        map(tuple((char('-'), many1(DIGIT))), |(_, end)| {
            Range::Range(
                start,
                u32::from_str_radix(&end.into_iter().collect::<String>(), 10).unwrap(),
            )
        }),
    )))(input)?;

    if let Some(r) = compl {
        Ok((input, r))
    } else {
        Ok((input, Range::OneOf(vec![start])))
    }
}

/// hex-val = "x" 1*HEXDIG [ 1*("." 1*HEXDIG) / ("-" 1*HEXDIG) ]
pub fn hex_val(input: &[u8]) -> IResult<&[u8], Range> {
    let (input, _) = char('x')(input)?;

    let (input, start) = map(many1(HEXDIG), |val| {
        u32::from_str_radix(&val.into_iter().collect::<String>(), 16).unwrap()
    })(input)?;

    let (input, compl) = opt(alt((
        map(many1(tuple((char('.'), many1(HEXDIG)))), |pairs| {
            let mut all = vec![start];
            for (_, val) in pairs.into_iter() {
                all.push(u32::from_str_radix(&val.into_iter().collect::<String>(), 16).unwrap())
            }
            Range::OneOf(all)
        }),
        map(tuple((char('-'), many1(HEXDIG))), |(_, end)| {
            Range::Range(
                start,
                u32::from_str_radix(&end.into_iter().collect::<String>(), 16).unwrap(),
            )
        }),
    )))(input)?;

    if let Some(r) = compl {
        Ok((input, r))
    } else {
        Ok((input, Range::OneOf(vec![start])))
    }
}

/// prose-val = "<" *(%x20-3D / %x3F-7E) ">"
///             ; bracketed string of SP and VCHAR without angles
///             ; prose description, to be used as last resort
pub fn prose_val(input: &[u8]) -> IResult<&[u8], String> {
    let prose_val_chars = |x| match x {
        0x20..=0x3D | 0x3F..=0x7E => true,
        _ => false,
    };

    let (input, (_, val, _)) = tuple((char('<'), take_while(prose_val_chars), char('>')))(input)?;

    Ok((input, val.into_iter().map(|b| *b as char).collect()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rules() {
        let tests = vec![
            ("a = A\n", Rule::new("a", Node::Rulename("A".into()))),
            (
                "B = A / B\n",
                Rule::new(
                    "B",
                    Node::Alternation(vec![
                        Box::new(Node::Rulename("A".into())),
                        Box::new(Node::Rulename("B".into())),
                    ]),
                ),
            ),
            (
                "c = (A / B)\n",
                Rule::new(
                    "c",
                    Node::Group(Box::new(Node::Alternation(vec![
                        Box::new(Node::Rulename("A".into())),
                        Box::new(Node::Rulename("B".into())),
                    ]))),
                ),
            ),
            (
                "D = <this is prose>\n",
                Rule::new("D", Node::ProseVal("this is prose".into())),
            ),
            (
                "xXx = ((A B))\n",
                Rule::new(
                    "xXx",
                    Node::Group(Box::new(Node::Group(Box::new(Node::Concatenation(vec![
                        Box::new(Node::Rulename("A".into())),
                        Box::new(Node::Rulename("B".into())),
                    ]))))),
                ),
            ),
            (
                "a = 0*15\"-\"\n",
                Rule::new(
                    "a",
                    Node::Repetition {
                        repeat: Some(Repeat {
                            min: Some(0),
                            max: Some(15),
                        }),
                        node: Box::new(Node::CharVal("-".into())),
                    },
                ),
            ),
            (
                "a = *\"-\"\n",
                Rule::new(
                    "a",
                    Node::Repetition {
                        repeat: Some(Repeat {
                            min: None,
                            max: None,
                        }),
                        node: Box::new(Node::CharVal("-".into())),
                    },
                ),
            ),
        ];

        for (test, expected) in tests {
            let (remaining, got) = rule(test.as_bytes()).unwrap();
            assert!(remaining.is_empty());
            assert_eq!(got, expected);
        }
    }

    #[test]
    fn test_rulename() {
        assert_eq!(rulename(b"a").unwrap().1, "a");
        assert_eq!(rulename(b"A").unwrap().1, "A");
        assert_eq!(rulename(b"ab").unwrap().1, "ab");
        assert_eq!(rulename(b"Ab").unwrap().1, "Ab");
        assert_eq!(rulename(b"A-b").unwrap().1, "A-b");
    }

    #[test]
    fn test_alternation() {
        let (remaining, res) = alternation(b"A / \"xxx\"").unwrap();
        assert!(remaining.len() == 0);
        println!("{:?}", res);
    }

    #[test]
    fn test_repetition() {
        let (remaining, res) = repetition(b"1*1A").unwrap();
        assert!(remaining.len() == 0);
        println!("{:?}", res);
    }

    #[test]
    fn test_num_val() {
        let expected = Range::OneOf(vec![0x00, 0x0A, 0xff]);
        let got1 = num_val(b"%b0.1010.11111111");
        let got2 = num_val(b"%d0.10.255");
        let got3 = num_val(b"%x0.A.ff");
        assert_eq!(expected, got1.unwrap().1);
        assert_eq!(expected, got2.unwrap().1);
        assert_eq!(expected, got3.unwrap().1);
    }

    #[test]
    fn test_bin_val() {
        let expected = Range::OneOf(vec![0x00, 0x03, 0xff]);
        let got = bin_val(b"b00.11.11111111");
        assert_eq!(expected, got.unwrap().1);

        let expected = Range::Range(0, 255);
        let got = bin_val(b"b00-11111111");
        assert_eq!(expected, got.unwrap().1)
    }

    #[test]
    fn test_dec_val() {
        let expected = Range::OneOf(vec![0, 42, 255]);
        let got = dec_val(b"d0.42.255");
        assert_eq!(expected, got.unwrap().1);

        let expected = Range::Range(0, 255);
        let got = dec_val(b"d0-255");
        assert_eq!(expected, got.unwrap().1)
    }

    #[test]
    fn test_hex_val() {
        let expected = Range::OneOf(vec![0xCA, 0xFF, 0xEE]);
        let got = hex_val(b"xCA.FF.EE");
        assert_eq!(expected, got.unwrap().1);

        let expected = Range::Range(0, 255);
        let got = hex_val(b"x00-FF");
        assert_eq!(expected, got.unwrap().1)
    }

    #[test]
    fn test_prose_val() {
        assert_eq!("Hello, World!", prose_val(b"<Hello, World!>").unwrap().1)
    }
}
