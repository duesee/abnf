#![warn(missing_docs)]
#![warn(missing_doc_code_examples)]

//! A crate for parsing ABNF definitions ([RFC5234](https://tools.ietf.org/html/rfc5234))
//!
//! Two functions are exposed for now, [rulelist](fn.rulelist.html) and [rule](fn.rule.html).
//! They cover the use case, where the complete ABNF definition is provided as a string.
//!
//! On success, both functions return `Ok(...)` with the parsed object.
//! If the ABNF definition contains a syntax error, both functions return `Err(ParsingError)`.
//! `ParsingError` is intended to be `Display`ed to a user and should help correcting mistakes in the
//! provided ABNF definition.
//!
//! It is also possible to create rules manually as showed in the example in the [types](types/index.html) module.
//!
//! # Example
//!
//! ```
//! use abnf::rulelist;
//!
//! // Note: mind the trailing newline!
//! match rulelist("a = b\nc = *d\n") {
//!     Ok(rules) => {
//!         for rule in &rules {
//!             println!("{:#?}\n", rule);
//!         }
//!     },
//!     Err(error) => eprintln!("{}", error),
//! }
//! ```

use crate::types::*;
use abnf_core::{complete::*, is_ALPHA, is_DIGIT};
use nom::{
    branch::alt,
    bytes::complete::{tag, take_until, take_while},
    character::complete::char,
    combinator::{all_consuming, map, opt, recognize, value},
    error::{convert_error, ParseError, VerboseError},
    multi::{many0, many1, separated_list1},
    sequence::{delimited, preceded, terminated, tuple},
    IResult,
};

pub mod error;
pub mod types;

/// Parses a list of multiple ABNF rules.
/// Returns `Ok(Vec<Rule>)` when everything went well and `Err(ParsingError)` in case of syntax errors.
///
/// **Note**: `input` must end with a newline and whitespace must not appear before the rulename.
/// (This may be relaxed in the future.)
///
/// # Example
///
/// ```
/// use abnf::rulelist;
///
/// match rulelist("a = b\nc = *d\n") {
///     Ok(rules) => println!("{:#?}", rules),
///     Err(error) => eprintln!("{}", error),
/// }
/// ```
pub fn rulelist(input: &str) -> Result<Vec<Rule>, crate::error::ParseError> {
    match all_consuming(rulelist_internal::<VerboseError<&str>>)(input) {
        Ok((remaining, rules)) => {
            assert!(remaining.is_empty());
            Ok(rules)
        }
        Err(error) => match error {
            nom::Err::Incomplete(_) => unreachable!(),
            nom::Err::Error(e) | nom::Err::Failure(e) => Err(crate::error::ParseError {
                message: convert_error(input, e),
            }),
        },
    }
}

/// Parses a single ABNF rule.
/// Returns `Ok(Rule)` when everything went well and `Err(ParsingError)` in case of syntax errors.
///
/// **Note**: `input` must end with a newline and whitespace must not appear before the rulename.
/// (This may be relaxed in the future.)
///
/// # Example
///
/// ```
/// use abnf::rule;
///
/// match rule("a = b / c / *d\n") {
///    Ok(rules) => println!("{:#?}", rules),
///    Err(error) => eprintln!("{}", error),
/// }
/// ```
pub fn rule(input: &str) -> Result<Rule, crate::error::ParseError> {
    match all_consuming(rule_internal::<VerboseError<&str>>)(input) {
        Ok((remaining, rule)) => {
            assert!(remaining.is_empty());
            Ok(rule)
        }
        Err(error) => match error {
            nom::Err::Incomplete(_) => unreachable!(),
            nom::Err::Error(e) | nom::Err::Failure(e) => Err(crate::error::ParseError {
                message: convert_error(input, e),
            }),
        },
    }
}

/// ```abnf
/// rulelist = 1*( rule / (*WSP c-nl) )
/// ; Errata ID: 3076
/// ```
fn rulelist_internal<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, Vec<Rule>, E> {
    let mut parser = many1(alt((
        map(rule_internal, Some),
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

/// ```abnf
/// rule = rulename defined-as elements c-nl
///         ; continues if next line starts
///         ;  with white space
/// ```
fn rule_internal<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&str, Rule, E> {
    let mut parser = tuple((rulename, defined_as, elements, c_nl));

    let (input, (name, definition, elements, _)) = parser(input)?;

    let rule = match definition {
        Kind::Basic => Rule::new(&name, elements),
        Kind::Incremental => Rule::incremental(&name, elements),
    };

    Ok((input, rule))
}

/// rulename = ALPHA *(ALPHA / DIGIT / "-")
fn rulename<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, String, E> {
    let is_valid = |x| is_ALPHA(x) || is_DIGIT(x) || x == '-';

    let (input, out) = recognize(tuple((ALPHA, take_while(is_valid))))(input)?;

    Ok((input, out.to_string()))
}

/// defined-as = *c-wsp ("=" / "=/") *c-wsp
fn defined_as<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, Kind, E> {
    delimited(
        many0(c_wsp),
        alt((
            value(Kind::Incremental, tag("=/")),
            value(Kind::Basic, tag("=")),
        )),
        many0(c_wsp),
    )(input)
}

/// elements = alternation *WSP
/// Errata ID: 2968
fn elements<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, Node, E> {
    terminated(alternation, many0(WSP))(input)
}

///c-wsp = WSP / (c-nl WSP)
fn c_wsp<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, &'a str, E> {
    alt((recognize(WSP), recognize(tuple((c_nl, recognize(WSP))))))(input)
}

/// c-nl = comment / CRLF ; comment or newline
fn c_nl<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, &'a str, E> {
    alt((comment, crlf_relaxed))(input)
}

/// comment = ";" *(WSP / VCHAR) CRLF
fn comment<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, &'a str, E> {
    recognize(tuple((char(';'), take_until("\n"), char('\n'))))(input)
}

/// alternation = concatenation *(*c-wsp "/" *c-wsp concatenation)
fn alternation<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, Node, E> {
    let separator = tuple((many0(c_wsp), char('/'), many0(c_wsp)));

    let (input, mut concatenations) = separated_list1(separator, concatenation)(input)?;

    // if alternation has only one child, do not wrap it in a `Node::Alternation`.
    if concatenations.len() == 1 {
        Ok((input, concatenations.pop().unwrap()))
    } else {
        Ok((input, Node::Alternation(concatenations)))
    }
}

/// concatenation = repetition *(1*c-wsp repetition)
fn concatenation<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, Node, E> {
    let separator = many1(c_wsp);

    let (input, mut repetitions) = separated_list1(separator, repetition)(input)?;

    // if concatenation has only one child, do not wrap it in a `Node::Concatenation`.
    if repetitions.len() == 1 {
        Ok((input, repetitions.pop().unwrap()))
    } else {
        Ok((input, Node::Concatenation(repetitions)))
    }
}

/// repetition = [repeat] element
fn repetition<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, Node, E> {
    let mut parser = tuple((opt(repeat), element));

    let (input, (repeat, node)) = parser(input)?;

    // if there is no repeat, do not wrap it in a `Node::Repetition`.
    if let Some(repeat) = repeat {
        Ok((input, Node::Repetition(Repetition::new(repeat, node))))
    } else {
        Ok((input, node))
    }
}

/// repeat = 1*DIGIT / (*DIGIT "*" *DIGIT)
fn repeat<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, Repeat, E> {
    let mut parser = alt((
        map(
            tuple((many0(DIGIT), char('*'), many0(DIGIT))),
            |(min, _, max)| {
                let min = if !min.is_empty() {
                    Some(usize::from_str_radix(&min.into_iter().collect::<String>(), 10).unwrap())
                } else {
                    None
                };

                let max = if !max.is_empty() {
                    Some(usize::from_str_radix(&max.into_iter().collect::<String>(), 10).unwrap())
                } else {
                    None
                };

                Repeat::with(min, max)
            },
        ),
        map(many1(DIGIT), |value| {
            let value = usize::from_str_radix(&value.into_iter().collect::<String>(), 10).unwrap();
            Repeat::with(Some(value), Some(value))
        }),
    ));

    let (input, repeat) = parser(input)?;

    Ok((input, repeat))
}

/// element = rulename / group / option / char-val / num-val / prose-val
fn element<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, Node, E> {
    alt((
        map(rulename, Node::Rulename),
        group,
        option,
        map(char_val, |str| Node::String(str.to_owned())),
        map(num_val, Node::TerminalValues),
        map(prose_val, |str| Node::Prose(str.to_owned())),
    ))(input)
}

/// group = "(" *c-wsp alternation *c-wsp ")"
fn group<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, Node, E> {
    let mut parser = delimited(
        char('('),
        delimited(many0(c_wsp), alternation, many0(c_wsp)),
        char(')'),
    );

    let (input, alternation) = parser(input)?;

    Ok((input, Node::Group(Box::new(alternation))))
}

/// option = "[" *c-wsp alternation *c-wsp "]"
fn option<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, Node, E> {
    let mut parser = delimited(
        char('['),
        delimited(many0(c_wsp), alternation, many0(c_wsp)),
        char(']'),
    );

    let (input, alternation) = parser(input)?;

    Ok((input, Node::Optional(Box::new(alternation))))
}

/// char-val = DQUOTE *(%x20-21 / %x23-7E) DQUOTE
fn char_val<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, &str, E> {
    let is_inner = |x| matches!(x, '\x20'..='\x21' | '\x23'..='\x7E');

    delimited(DQUOTE, take_while(is_inner), DQUOTE)(input)
}

/// num-val = "%" (bin-val / dec-val / hex-val)
fn num_val<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, TerminalValues, E> {
    preceded(char('%'), alt((bin_val, dec_val, hex_val)))(input)
}

/// bin-val = "b" 1*BIT [ 1*("." 1*BIT) / ("-" 1*BIT) ]
fn bin_val<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, TerminalValues, E> {
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
            TerminalValues::Concatenation(all)
        }),
        map(tuple((char('-'), many1(BIT))), |(_, end)| {
            TerminalValues::Range(
                start,
                u32::from_str_radix(&end.into_iter().collect::<String>(), 2)
                    .expect("should never happen"),
            )
        }),
    )))(input)?;

    if let Some(r) = compl {
        Ok((input, r))
    } else {
        Ok((input, TerminalValues::Concatenation(vec![start])))
    }
}

/// dec-val = "d" 1*DIGIT [ 1*("." 1*DIGIT) / ("-" 1*DIGIT) ]
fn dec_val<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, TerminalValues, E> {
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
            TerminalValues::Concatenation(all)
        }),
        map(tuple((char('-'), many1(DIGIT))), |(_, end)| {
            TerminalValues::Range(
                start,
                u32::from_str_radix(&end.into_iter().collect::<String>(), 10).unwrap(),
            )
        }),
    )))(input)?;

    if let Some(r) = compl {
        Ok((input, r))
    } else {
        Ok((input, TerminalValues::Concatenation(vec![start])))
    }
}

/// hex-val = "x" 1*HEXDIG [ 1*("." 1*HEXDIG) / ("-" 1*HEXDIG) ]
fn hex_val<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, TerminalValues, E> {
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
            TerminalValues::Concatenation(all)
        }),
        map(tuple((char('-'), many1(HEXDIG))), |(_, end)| {
            TerminalValues::Range(
                start,
                u32::from_str_radix(&end.into_iter().collect::<String>(), 16).unwrap(),
            )
        }),
    )))(input)?;

    if let Some(r) = compl {
        Ok((input, r))
    } else {
        Ok((input, TerminalValues::Concatenation(vec![start])))
    }
}

/// prose-val = "<" *(%x20-3D / %x3F-7E) ">"
fn prose_val<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, &str, E> {
    let is_inner = |x| matches!(x, '\x20'..='\x3D' | '\x3F'..='\x7E');

    delimited(char('<'), take_while(is_inner), char('>'))(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nom::error::VerboseError;
    use quickcheck::{Arbitrary, Gen};
    use quickcheck_macros::quickcheck;
    use rand::{distributions::Distribution, seq::SliceRandom, Rng};

    struct RulenameDistribution;

    impl Distribution<char> for RulenameDistribution {
        fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> char {
            *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-"
                .choose(rng)
                .unwrap() as char
        }
    }

    impl Arbitrary for Rule {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            let name: String = std::iter::repeat(())
                .map(|()| g.sample(RulenameDistribution))
                .take(7)
                .collect();
            let name = String::from("a") + &name;

            match Kind::arbitrary(g) {
                Kind::Basic => Rule::new(&name, Node::arbitrary(g)),
                Kind::Incremental => Rule::incremental(&name, Node::arbitrary(g)),
            }
        }
    }

    impl Arbitrary for Node {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            let name: String = std::iter::repeat(())
                .map(|()| g.sample(RulenameDistribution))
                .take(7)
                .collect();
            let name = String::from("a") + &name;

            match g.gen_range(0, 9) {
                0 => Node::Alternation(vec![Node::arbitrary(g), Node::arbitrary(g)]),
                1 => Node::Concatenation(vec![Node::arbitrary(g), Node::arbitrary(g)]),
                2 => Node::Repetition(Repetition::new(Repeat::arbitrary(g), Node::arbitrary(g))),
                3 => Node::Rulename(name), // TODO
                4 => Node::Group(Box::<Node>::arbitrary(g)),
                5 => Node::Optional(Box::<Node>::arbitrary(g)),
                6 => Node::String(name), // TODO
                7 => Node::TerminalValues(TerminalValues::arbitrary(g)),
                8 => Node::Prose(name), // TODO
                _ => unreachable!(),
            }
        }
    }

    impl Arbitrary for Kind {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            use Kind::*;
            [Basic, Incremental].choose(g).unwrap().clone()
        }
    }

    impl Arbitrary for Repeat {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            Repeat::with(Option::<usize>::arbitrary(g), Option::<usize>::arbitrary(g))
        }
    }

    impl Arbitrary for TerminalValues {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            use super::TerminalValues::*;
            [
                Concatenation(Vec::<u32>::arbitrary(g)),
                Range(u32::arbitrary(g), u32::arbitrary(g)),
            ]
            .choose(g)
            .unwrap()
            .clone()
        }
    }

    #[test]
    fn test_rules() {
        let tests = vec![
            ("a = A\n", Rule::new("a", Node::rulename("A"))),
            (
                "B = A / B\n",
                Rule::new(
                    "B",
                    Node::alternation(&[Node::rulename("A"), Node::rulename("B")]),
                ),
            ),
            (
                "c = (A / B)\n",
                Rule::new(
                    "c",
                    Node::group(Node::alternation(&[
                        Node::rulename("A"),
                        Node::rulename("B"),
                    ])),
                ),
            ),
            (
                "D = <this is prose>\n",
                Rule::new("D", Node::prose("this is prose")),
            ),
            (
                "xXx = ((A B))\n",
                Rule::new(
                    "xXx",
                    Node::group(Node::group(Node::concatenation(&[
                        Node::rulename("A"),
                        Node::rulename("B"),
                    ]))),
                ),
            ),
            (
                "a = 0*15\"-\"\n",
                Rule::new(
                    "a",
                    Node::repeat(Repeat::with(Some(0), Some(15)), Node::string("-")),
                ),
            ),
            (
                "a = *\"-\"\n",
                Rule::new("a", Node::repeat(Repeat::unbounded(), Node::string("-"))),
            ),
        ];

        for (test, expected) in tests {
            let (remaining, got) = rule_internal::<VerboseError<&str>>(test).unwrap();
            assert!(remaining.is_empty());
            assert_eq!(got, expected);
        }
    }

    #[test]
    fn test_rulename() {
        assert_eq!(rulename::<VerboseError<&str>>("a").unwrap().1, "a");
        assert_eq!(rulename::<VerboseError<&str>>("A").unwrap().1, "A");
        assert_eq!(rulename::<VerboseError<&str>>("ab").unwrap().1, "ab");
        assert_eq!(rulename::<VerboseError<&str>>("Ab").unwrap().1, "Ab");
        assert_eq!(rulename::<VerboseError<&str>>("A-b").unwrap().1, "A-b");
    }

    #[test]
    fn test_alternation() {
        let (remaining, res) = alternation::<VerboseError<&str>>("A / \"xxx\"").unwrap();
        assert!(remaining.len() == 0);
        println!("{:?}", res);
    }

    #[test]
    fn test_repetition() {
        let (remaining, res) = repetition::<VerboseError<&str>>("1*1A").unwrap();
        assert!(remaining.len() == 0);
        println!("{:?}", res);
    }

    #[test]
    fn test_num_val() {
        let expected = TerminalValues::Concatenation(vec![0x00, 0x0A, 0xff]);
        let got1 = num_val::<VerboseError<&str>>("%b0.1010.11111111");
        let got2 = num_val::<VerboseError<&str>>("%d0.10.255");
        let got3 = num_val::<VerboseError<&str>>("%x0.A.ff");
        assert_eq!(expected, got1.unwrap().1);
        assert_eq!(expected, got2.unwrap().1);
        assert_eq!(expected, got3.unwrap().1);
    }

    #[test]
    fn test_bin_val() {
        let expected = TerminalValues::Concatenation(vec![0x00, 0x03, 0xff]);
        let got = bin_val::<VerboseError<&str>>("b00.11.11111111");
        assert_eq!(expected, got.unwrap().1);

        let expected = TerminalValues::Range(0, 255);
        let got = bin_val::<VerboseError<&str>>("b00-11111111");
        assert_eq!(expected, got.unwrap().1)
    }

    #[test]
    fn test_dec_val() {
        let expected = TerminalValues::Concatenation(vec![0, 42, 255]);
        let got = dec_val::<VerboseError<&str>>("d0.42.255");
        assert_eq!(expected, got.unwrap().1);

        let expected = TerminalValues::Range(0, 255);
        let got = dec_val::<VerboseError<&str>>("d0-255");
        assert_eq!(expected, got.unwrap().1)
    }

    #[test]
    fn test_hex_val() {
        let expected = TerminalValues::Concatenation(vec![0xCA, 0xFF, 0xEE]);
        let got = hex_val::<VerboseError<&str>>("xCA.FF.EE");
        assert_eq!(expected, got.unwrap().1);

        let expected = TerminalValues::Range(0, 255);
        let got = hex_val::<VerboseError<&str>>("x00-FF");
        assert_eq!(expected, got.unwrap().1)
    }

    #[test]
    fn test_prose_val() {
        assert_eq!(
            "Hello, World!",
            prose_val::<VerboseError<&str>>("<Hello, World!>")
                .unwrap()
                .1
        )
    }

    #[test]
    fn test_definition() {
        let tests = vec![
            ("a =/ A\n", Rule::incremental("a", Node::rulename("A"))),
            (
                "B =/ A / B\n",
                Rule::incremental(
                    "B",
                    Node::alternation(&[Node::rulename("A"), Node::rulename("B")]),
                ),
            ),
        ];

        for (test, expected) in tests {
            let (remaining, got) = rule_internal::<VerboseError<&str>>(test).unwrap();
            assert!(remaining.is_empty());
            assert_eq!(got, expected);
        }
    }

    #[quickcheck]
    fn test_explore_nesting(test: Rule) {
        // FIXME: This test can not fail currently.
        // Serialize an arbitrary rule to a string and check if it is parsed correctly.
        // This is useful to see how much of the API can be exposed without getting weird errors.
        //
        // Should...
        //     rule == deserialize(serialize(rule))
        // also be true?
        //
        // Findings:
        // * Repetition(Repetition(...)) is not parsable.
        let printed = test.to_string() + "\n";

        if let Err(_) = rule_internal::<VerboseError<&str>>(&printed) {
            println!("# Found interesting rule:");
            println!("{}", test);
        }
    }

    #[test]
    fn test_repetition_repetition() {
        // FIXME: This test can not fail currently.
        let rule = Rule::new(
            "rule",
            Node::repeat(
                Repeat::with(Some(1), Some(12)),
                Node::repeat(Repeat::with(Some(1), Some(2)), Node::prose("test")),
            ),
        );
        println!("{}", rule);
    }

    #[test]
    fn test_comment_unicode() {
        let (remaining, _) = comment::<VerboseError<&str>>(";a\n").unwrap();
        assert_eq!(remaining, "");
        let (remaining, _) = comment::<VerboseError<&str>>("; a\n").unwrap();
        assert_eq!(remaining, "");
        let (remaining, _) = comment::<VerboseError<&str>>("; a \n").unwrap();
        assert_eq!(remaining, "");
        let (remaining, _) = comment::<VerboseError<&str>>("; a \r\n").unwrap();
        assert_eq!(remaining, "");
        let (remaining, _) = comment::<VerboseError<&str>>(";²\n").unwrap();
        assert_eq!(remaining, "");
        let (remaining, _) = comment::<VerboseError<&str>>("; ²\n").unwrap();
        assert_eq!(remaining, "");
        let (remaining, _) = comment::<VerboseError<&str>>("; ² \n").unwrap();
        assert_eq!(remaining, "");
        let (remaining, _) = comment::<VerboseError<&str>>("; ² \r\n").unwrap();
        assert_eq!(remaining, "");

        let (remaining, _) = comment::<VerboseError<&str>>(";a\nx").unwrap();
        assert_eq!(remaining, "x");
        let (remaining, _) = comment::<VerboseError<&str>>("; a\nx").unwrap();
        assert_eq!(remaining, "x");
        let (remaining, _) = comment::<VerboseError<&str>>("; a \nx").unwrap();
        assert_eq!(remaining, "x");
        let (remaining, _) = comment::<VerboseError<&str>>("; a \r\nx").unwrap();
        assert_eq!(remaining, "x");
        let (remaining, _) = comment::<VerboseError<&str>>(";²\nx").unwrap();
        assert_eq!(remaining, "x");
        let (remaining, _) = comment::<VerboseError<&str>>("; ²\nx").unwrap();
        assert_eq!(remaining, "x");
        let (remaining, _) = comment::<VerboseError<&str>>("; ² \nx").unwrap();
        assert_eq!(remaining, "x");
        let (remaining, _) = comment::<VerboseError<&str>>("; ² \r\nx").unwrap();
        assert_eq!(remaining, "x");
    }

    #[test]
    fn test_error_handling() {
        let data = "a = *b\n\n\nb = *x";
        let error = rulelist(data).unwrap_err();
        println!("{}", error);
    }

    #[test]
    fn test_file_abnf_core() {
        let imap = std::fs::read_to_string("examples/assets/abnf_core.abnf").unwrap();
        rulelist(&imap).unwrap();
    }

    #[test]
    fn test_file_abnf() {
        let imap = std::fs::read_to_string("examples/assets/abnf.abnf").unwrap();
        rulelist(&imap).unwrap();
    }

    #[test]
    fn test_file_imap() {
        let imap = std::fs::read_to_string("examples/assets/imap.abnf").unwrap();
        rulelist(&imap).unwrap();
    }
}
