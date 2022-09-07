#![warn(missing_docs)]

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

use abnf_core::{complete::*, is_ALPHA, is_BIT, is_DIGIT, is_HEXDIG};
use nom::{
    branch::alt,
    bytes::complete::{tag, take_until, take_while, take_while1},
    character::complete::char,
    combinator::{all_consuming, map, opt, recognize, value},
    error::{convert_error, ErrorKind, ParseError, VerboseError},
    multi::{many0, many1, separated_list1},
    sequence::{delimited, preceded, separated_pair, terminated, tuple},
    IResult,
};

use crate::types::*;

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
/// // Note: mind the trailing newline!
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
/// match rule("a = b / c / *d") {
///    Ok(rules) => println!("{:#?}", rules),
///    Err(error) => eprintln!("{}", error),
/// }
/// ```
pub fn rule(input: &str) -> Result<Rule, crate::error::ParseError> {
    match all_consuming(rule_internal_single::<VerboseError<&str>>)(input) {
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

// -------------------------------------------------------------------------------------------------

/// ```abnf
/// rulelist = 1*( rule / (*WSP c-nl) )
///             ; Errata ID: 3076
/// ```
fn rulelist_internal<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, Vec<Rule>, E> {
    let mut parser = many1(alt((
        map(rule_internal, Some),
        map(tuple((many0(WSP), c_nl)), |_| None),
    )));

    let (input, rulelist) = parser(input)?;

    Ok((input, rulelist.into_iter().flatten().collect()))
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

/// Whitespace and comments before rule allowed, no trailing newline required.
fn rule_internal_single<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&str, Rule, E> {
    let mut parser = tuple((
        many0(alt((c_nl, recognize(WSP)))),
        rulename,
        defined_as,
        elements,
        opt(c_nl),
    ));

    let (input, (_, name, definition, elements, _)) = parser(input)?;

    let rule = match definition {
        Kind::Basic => Rule::new(&name, elements),
        Kind::Incremental => Rule::incremental(&name, elements),
    };

    Ok((input, rule))
}

/// ```abnf
/// rulename = ALPHA *(ALPHA / DIGIT / "-")
/// ```
fn rulename<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, &str, E> {
    let is_valid = |x| is_ALPHA(x) || is_DIGIT(x) || x == '-';

    recognize(tuple((ALPHA, take_while(is_valid))))(input)
}

/// Basic rules definition and incremental alternatives.
///
/// ```abnf
/// defined-as = *c-wsp ("=" / "=/") *c-wsp
/// ```
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

/// ```abnf
/// elements = alternation *WSP
///             ; Errata ID: 2968
/// ```
fn elements<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, Node, E> {
    terminated(alternation, many0(WSP))(input)
}

/// ```abnf
/// alternation = concatenation *(*c-wsp "/" *c-wsp concatenation)
/// ```
fn alternation<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, Node, E> {
    let separator = tuple((many0(c_wsp), char('/'), many0(c_wsp)));

    let (input, mut concatenations) = separated_list1(separator, concatenation)(input)?;

    // if there is only a single element in the alternatives, do not wrap it in a `Node::Alternatives`.
    if concatenations.len() == 1 {
        Ok((input, concatenations.pop().unwrap()))
    } else {
        Ok((input, Node::Alternatives(concatenations)))
    }
}

/// ```abnf
/// concatenation = repetition *(1*c-wsp repetition)
/// ```
fn concatenation<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, Node, E> {
    let separator = many1(c_wsp);

    let (input, mut repetitions) = separated_list1(separator, repetition)(input)?;

    // if there is only a single element in the concatenation, do not wrap it in a `Node::Concatenation`.
    if repetitions.len() == 1 {
        Ok((input, repetitions.pop().unwrap()))
    } else {
        Ok((input, Node::Concatenation(repetitions)))
    }
}

/// ```abnf
/// repetition = [repeat] element
/// ```
fn repetition<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, Node, E> {
    let mut parser = tuple((opt(repeat), element));

    let (input, (repeat, node)) = parser(input)?;

    // if there is no repeat, do not wrap it in a `Node::Repetition`.
    if let Some(repeat) = repeat {
        Ok((input, Node::repetition(repeat, node)))
    } else {
        Ok((input, node))
    }
}

/// ```abnf
/// repeat = 1*DIGIT / (*DIGIT "*" *DIGIT)
/// ```
fn repeat<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, Repeat, E> {
    alt((
        map(
            separated_pair(opt(dec_usize), char('*'), opt(dec_usize)),
            |(min, max)| Repeat::Variable { min, max },
        ),
        map(dec_usize, Repeat::Specific),
    ))(input)
}

/// ```abnf
/// element = rulename / group / option / char-val / num-val / prose-val
/// ```
fn element<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, Node, E> {
    alt((
        map(rulename, |rulename| Node::Rulename(rulename.to_owned())),
        group,
        option,
        map(char_val, Node::String),
        map(num_val, Node::TerminalValues),
        map(prose_val, |str| Node::Prose(str.to_owned())),
    ))(input)
}

/// ```abnf
/// group = "(" *c-wsp alternation *c-wsp ")"
/// ```
fn group<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, Node, E> {
    let mut parser = delimited(
        char('('),
        delimited(many0(c_wsp), alternation, many0(c_wsp)),
        char(')'),
    );

    let (input, alternation) = parser(input)?;

    Ok((input, Node::Group(Box::new(alternation))))
}

/// ```abnf
/// option = "[" *c-wsp alternation *c-wsp "]"
/// ```
fn option<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, Node, E> {
    let mut parser = delimited(
        char('['),
        delimited(many0(c_wsp), alternation, many0(c_wsp)),
        char(']'),
    );

    let (input, alternation) = parser(input)?;

    Ok((input, Node::Optional(Box::new(alternation))))
}

/// ```abnf
/// char-val = case-insensitive-string / case-sensitive-string
/// ```
fn char_val<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&str, StringLiteral, E> {
    alt((
        map(case_insensitive_string, |str| {
            StringLiteral::case_insensitive(str.to_owned())
        }),
        map(case_sensitive_string, |str| {
            StringLiteral::case_sensitive(str.to_owned())
        }),
    ))(input)
}

/// ```abnf
/// case-insensitive-string = [ "%i" ] quoted-string
/// ```
fn case_insensitive_string<'a, E: ParseError<&'a str>>(
    input: &'a str,
) -> IResult<&'a str, &str, E> {
    let marker = preceded(char('%'), alt((char('i'), char('I'))));
    preceded(opt(marker), quoted_string)(input)
}

/// ```abnf
/// case-sensitive-string = "%s" quoted-string
/// ```
fn case_sensitive_string<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, &str, E> {
    let marker = preceded(char('%'), alt((char('i'), char('I'))));
    preceded(marker, quoted_string)(input)
}

/// Quoted string of SP and VCHAR without DQUOTE
///
/// ```abnf
/// quoted-string = DQUOTE *(%x20-21 / %x23-7E) DQUOTE
/// ```
fn quoted_string<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, &str, E> {
    let is_inner = |x| matches!(x, '\x20'..='\x21' | '\x23'..='\x7E');

    delimited(DQUOTE, take_while(is_inner), DQUOTE)(input)
}

/// ```abnf
/// num-val = "%" (bin-val / dec-val / hex-val)
/// ```
fn num_val<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, TerminalValues, E> {
    preceded(char('%'), alt((bin_val, dec_val, hex_val)))(input)
}

/// Series of concatenated bit values or single ONEOF range
///
/// ```abnf
/// bin-val = "b" 1*BIT [ 1*("." 1*BIT) / ("-" 1*BIT) ]
/// ```
fn bin_val<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, TerminalValues, E> {
    preceded(
        char('b'),
        alt((
            map(
                separated_pair(bin_u32, char('-'), bin_u32),
                |(start, end)| TerminalValues::Range(start, end),
            ),
            map(
                separated_list1(char('.'), bin_u32),
                TerminalValues::Concatenation,
            ),
        )),
    )(input)
}

/// ```abnf
/// dec-val = "d" 1*DIGIT [ 1*("." 1*DIGIT) / ("-" 1*DIGIT) ]
/// ```
fn dec_val<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, TerminalValues, E> {
    preceded(
        char('d'),
        alt((
            map(
                separated_pair(dec_u32, char('-'), dec_u32),
                |(start, end)| TerminalValues::Range(start, end),
            ),
            map(
                separated_list1(char('.'), dec_u32),
                TerminalValues::Concatenation,
            ),
        )),
    )(input)
}

/// ```abnf
/// hex-val = "x" 1*HEXDIG [ 1*("." 1*HEXDIG) / ("-" 1*HEXDIG) ]
/// ```
fn hex_val<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, TerminalValues, E> {
    preceded(
        char('x'),
        alt((
            map(
                separated_pair(hex_u32, char('-'), hex_u32),
                |(start, end)| TerminalValues::Range(start, end),
            ),
            map(
                separated_list1(char('.'), hex_u32),
                TerminalValues::Concatenation,
            ),
        )),
    )(input)
}

/// Bracketed string of SP and VCHAR without angles prose description, to be used as last resort.
///
/// ```abnf
/// prose-val = "<" *(%x20-3D / %x3F-7E) ">"
/// ```
fn prose_val<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, &str, E> {
    let is_inner = |x| matches!(x, '\x20'..='\x3D' | '\x3F'..='\x7E');

    delimited(char('<'), take_while(is_inner), char('>'))(input)
}

/// Comment or Newline.
///
/// ```abnf
/// c-nl = comment / CRLF
/// ```
fn c_nl<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, &'a str, E> {
    alt((comment, crlf_relaxed))(input)
}

/// ```abnf
/// comment = ";" *(WSP / VCHAR) CRLF
///
/// Relaxed, see <https://github.com/duesee/abnf/issues/11>.
/// ```
fn comment<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, &'a str, E> {
    recognize(tuple((char(';'), take_until("\n"), char('\n'))))(input)
}

/// ```abnf
/// c-wsp = WSP / (c-nl WSP)
/// ```
fn c_wsp<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, &'a str, E> {
    alt((recognize(WSP), recognize(tuple((c_nl, recognize(WSP))))))(input)
}

// -------------------------------------------------------------------------------------------------

fn bin_u32<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, u32, E> {
    let (remaining, out) = take_while1(is_BIT)(input)?;
    match u32::from_str_radix(out, 2) {
        Ok(num) => Ok((remaining, num)),
        Err(_) => Err(nom::Err::Failure(nom::error::make_error(
            // FIXME: use error
            input,
            ErrorKind::Verify,
        ))),
    }
}

fn dec_u32<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, u32, E> {
    let (remaining, out) = take_while1(is_DIGIT)(input)?;
    match u32::from_str_radix(out, 10) {
        Ok(num) => Ok((remaining, num)),
        Err(_) => Err(nom::Err::Failure(nom::error::make_error(
            // FIXME: use error
            input,
            ErrorKind::Verify,
        ))),
    }
}

fn dec_usize<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, usize, E> {
    let (remaining, out) = take_while1(is_DIGIT)(input)?;
    match usize::from_str_radix(out, 10) {
        Ok(num) => Ok((remaining, num)),
        Err(_) => Err(nom::Err::Failure(nom::error::make_error(
            // FIXME: use error
            input,
            ErrorKind::Verify,
        ))),
    }
}

fn hex_u32<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, u32, E> {
    let (remaining, out) = take_while1(is_HEXDIG)(input)?;
    match u32::from_str_radix(out, 16) {
        Ok(num) => Ok((remaining, num)),
        Err(_) => Err(nom::Err::Failure(nom::error::make_error(
            // FIXME: use error
            input,
            ErrorKind::Verify,
        ))),
    }
}

#[cfg(test)]
mod tests {
    use nom::error::VerboseError;
    use quickcheck::{Arbitrary, Gen};
    use quickcheck_macros::quickcheck;
    use rand::{distributions::Distribution, seq::SliceRandom, thread_rng, Rng};

    use super::*;

    struct RulenameDistribution;

    impl Distribution<char> for RulenameDistribution {
        fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> char {
            *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-"
                .choose(rng)
                .unwrap() as char
        }
    }

    /// Uniform char distribution in the set `%x20-21 / %x23-7E`.
    struct StringDistribution;

    impl Distribution<char> for StringDistribution {
        fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> char {
            let mut i = rng.gen_range(0x20u32..=0x7d);

            if i > 0x21 {
                // avoid %x22
                i += 0x01
            }

            char::from_u32(i).unwrap()
        }
    }

    impl Arbitrary for Rule {
        fn arbitrary(g: &mut Gen) -> Self {
            let rng = thread_rng();
            let name: String = RulenameDistribution.sample_iter(rng).take(7).collect();
            let name = String::from("a") + &name;

            match Kind::arbitrary(g) {
                Kind::Basic => Rule::new(&name, Node::arbitrary(g)),
                Kind::Incremental => Rule::incremental(&name, Node::arbitrary(g)),
            }
        }
    }

    impl Arbitrary for Node {
        fn arbitrary(g: &mut Gen) -> Self {
            let mut rng = thread_rng();
            let name: String = RulenameDistribution.sample_iter(&mut rng).take(7).collect();
            let name = String::from("a") + &name;

            match rng.gen_range(0..=8) {
                0 => Node::Alternatives(vec![Node::arbitrary(g), Node::arbitrary(g)]),
                1 => Node::Concatenation(vec![Node::arbitrary(g), Node::arbitrary(g)]),
                2 => Node::Repetition {
                    repeat: Repeat::arbitrary(g),
                    node: Box::new(Node::arbitrary(g)),
                },
                3 => Node::Rulename(name), // TODO
                4 => Node::Group(Box::<Node>::arbitrary(g)),
                5 => Node::Optional(Box::<Node>::arbitrary(g)),
                6 => Node::String(StringLiteral::arbitrary(g)),
                7 => Node::TerminalValues(TerminalValues::arbitrary(g)),
                8 => Node::Prose(name), // TODO
                _ => unreachable!(),
            }
        }
    }

    impl Arbitrary for StringLiteral {
        fn arbitrary(_: &mut Gen) -> Self {
            let mut rng = thread_rng();

            let len = rand_distr::Binomial::new(20, 0.3).unwrap().sample(&mut rng) as usize;
            let value = StringDistribution.sample_iter(&mut rng).take(len).collect();
            let case_sensitive = rand::distributions::Bernoulli::new(0.5)
                .unwrap()
                .sample(&mut rng);

            Self::new(value, case_sensitive)
        }
    }

    impl Arbitrary for Kind {
        fn arbitrary(_: &mut Gen) -> Self {
            match thread_rng().gen_range(0..=1) {
                0 => Kind::Basic,
                1 => Kind::Incremental,
                _ => unreachable!(),
            }
        }
    }

    impl Arbitrary for Repeat {
        fn arbitrary(g: &mut Gen) -> Self {
            match thread_rng().gen_range(0..=1) {
                0 => Repeat::specific(<usize>::arbitrary(g)),
                1 => Repeat::variable(Option::<usize>::arbitrary(g), Option::<usize>::arbitrary(g)),
                _ => unreachable!(),
            }
        }
    }

    impl Arbitrary for TerminalValues {
        fn arbitrary(g: &mut Gen) -> Self {
            match thread_rng().gen_range(0..=1) {
                0 => TerminalValues::Concatenation(Vec::<u32>::arbitrary(g)),
                1 => TerminalValues::Range(u32::arbitrary(g), u32::arbitrary(g)),
                _ => unreachable!(),
            }
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
                    Node::alternatives(&[Node::rulename("A"), Node::rulename("B")]),
                ),
            ),
            (
                "c = (A / B)\n",
                Rule::new(
                    "c",
                    Node::group(Node::alternatives(&[
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
                    Node::repetition(
                        Repeat::variable(Some(0), Some(15)),
                        Node::string("-", false),
                    ),
                ),
            ),
            (
                "a = *\"-\"\n",
                Rule::new(
                    "a",
                    Node::repetition(Repeat::unbounded(), Node::string("-", false)),
                ),
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
                    Node::alternatives(&[Node::rulename("A"), Node::rulename("B")]),
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
            println!("{:#?}", test);
            println!("{}", test);
        }
    }

    #[test]
    fn test_repetition_repetition() {
        // FIXME: This test can not fail currently.
        let rule = Rule::new(
            "rule",
            Node::repetition(
                Repeat::variable(Some(1), Some(12)),
                Node::repetition(Repeat::variable(Some(1), Some(2)), Node::prose("test")),
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

    #[test]
    fn test_relaxed_rule_parsing() {
        let expected = Rule::new("rule", Node::rulename("A"));

        let tests = [
            "rule = A",
            "rule = A\n",
            " rule = A",
            " rule = A\n",
            "; Comment\nrule = A",
            "; Comment\nrule = A\n",
            "\n; Comment\nrule = A",
            "\n; Comment\nrule = A\n",
            "\n; Comment\n rule = A",
            "\n; Comment\n rule = A\n",
            "\n\n   \n   \n \n; Comment \n\n\n  \n \n rule = \n A",
        ];

        for test in &tests {
            println!("[#] {}", test);

            let got = rule(test).unwrap();
            println!("[#] {:?}", got);

            assert_eq!(expected, got);
            println!("-------------------------------------------");
        }
    }
}
