//!
//! Parsing of ABNF
//!
//! See https://tools.ietf.org/html/rfc5234#section-4
//!

use crate::{core::*, types::*};

use nom::branch::alt;
use nom::bytes::complete::{tag, take_while};
use nom::character::complete::char;
use nom::combinator::{cut, map, opt};
use nom::error::ParseError;
use nom::multi::{many0, many1};
use nom::sequence::tuple;
use nom::IResult;

/// ```abnf
/// ; Errata ID: 3076
/// rulelist = 1*( rule / (*WSP c-nl) )
/// ```
pub fn rulelist<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, Vec<Rule>, E> {
    let parser = many1(alt((
        map(rule, Some),
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
pub fn rule<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&str, Rule, E> {
    let parser = tuple((rulename, defined_as, elements, cut(c_nl)));

    let (input, (name, definition, elements, _)) = parser(input)?;

    let rule = match definition {
        Kind::Basic => Rule::new(&name, elements),
        Kind::Incremental => Rule::incremental(&name, elements),
    };

    Ok((input, rule))
}

/// rulename = ALPHA *(ALPHA / DIGIT / "-")
pub fn rulename<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, String, E> {
    let valid = |x| is_ALPHA(x) || is_DIGIT(x) || x == '-';

    let (input, (head, tail)) = tuple((ALPHA, take_while(valid)))(input)?;

    let mut val = String::new();
    val.push(head);
    val.push_str(tail);

    Ok((input, val))
}

/// defined-as = *c-wsp ("=" / "=/") *c-wsp
///               ; basic rules definition and
///               ;  incremental alternatives
pub fn defined_as<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, Kind, E> {
    let parser = tuple((
        many0(c_wsp),
        alt((
            map(tag("=/"), |_| Kind::Incremental),
            map(tag("="), |_| Kind::Basic),
        )),
        many0(c_wsp),
    ));

    let (input, (_, definition, _)) = parser(input)?;

    Ok((input, definition))
}

/// elements = alternation *WSP
/// Errata ID: 2968
pub fn elements<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, Node, E> {
    let parser = tuple((alternation, many0(WSP)));

    let (input, (alternation, _)) = parser(input)?;

    Ok((input, alternation))
}

///c-wsp = WSP / (c-nl WSP)
pub fn c_wsp<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, (), E> {
    let parser = alt((map(WSP, |_| ()), map(tuple((c_nl, WSP)), |_| ())));

    let (input, _) = parser(input)?;

    Ok((input, ()))
}

/// c-nl = comment / CRLF ; comment or newline
pub fn c_nl<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, (), E> {
    let parser = alt((comment, map(CRLF, |_| ())));

    let (input, _) = parser(input)?;

    Ok((input, ()))
}

/// comment = ";" *(WSP / VCHAR) CRLF
pub fn comment<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, (), E> {
    let valid = |x| is_WSP(x) || is_VCHAR(x);

    let (input, (_, _, _)) = tuple((char(';'), take_while(valid), CRLF))(input)?;

    Ok((input, ()))
}

/// alternation = concatenation *(*c-wsp "/" *c-wsp concatenation)
pub fn alternation<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, Node, E> {
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

    let mut concatenations = vec![head];

    for (_, _, _, item) in tail {
        concatenations.push(item)
    }

    // if alternation has only one child, do not wrap it in a `Node::Alternation`.
    if concatenations.len() == 1 {
        Ok((input, concatenations.pop().unwrap()))
    } else {
        Ok((input, Node::Alternation(concatenations)))
    }
}

/// concatenation = repetition *(1*c-wsp repetition)
pub fn concatenation<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, Node, E> {
    let parser = tuple((repetition, many0(tuple((many1(c_wsp), repetition)))));

    let (input, (head, tail)) = parser(input)?;

    let mut repetitions = vec![head];

    for (_, item) in tail {
        repetitions.push(item)
    }

    // if concatenation has only one child, do not wrap it in a `Node::Concatenation`.
    if repetitions.len() == 1 {
        Ok((input, repetitions.pop().unwrap()))
    } else {
        Ok((input, Node::Concatenation(repetitions)))
    }
}

/// repetition = [repeat] element
pub fn repetition<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, Node, E> {
    let parser = tuple((opt(repeat), element));

    let (input, (repeat, node)) = parser(input)?;

    // if there is no repeat, do not wrap it in a `Node::Repetition`.
    if let Some(repeat) = repeat {
        Ok((input, Node::Repetition(Repetition::new(repeat, node))))
    } else {
        Ok((input, node))
    }
}

/// repeat = 1*DIGIT / (*DIGIT "*" *DIGIT)
pub fn repeat<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, Repeat, E> {
    let parser = alt((
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
        map(many1(DIGIT), |min| {
            let min = usize::from_str_radix(&min.into_iter().collect::<String>(), 10).unwrap();
            Repeat::with(Some(min), Some(min))
        }),
    ));

    let (input, repeat) = parser(input)?;

    Ok((input, repeat))
}

/// element = rulename / group / option / char-val / num-val / prose-val
pub fn element<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, Node, E> {
    let parser = alt((
        map(rulename, Node::Rulename),
        map(group, |e| e),
        map(option, |e| e),
        map(char_val, |str| Node::CharVal(str.to_owned())),
        map(num_val, Node::NumVal),
        map(prose_val, |str| Node::ProseVal(str.to_owned())),
    ));

    let (input, val) = parser(input)?;

    Ok((input, val))
}

/// group = "(" *c-wsp alternation *c-wsp ")"
pub fn group<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, Node, E> {
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
pub fn option<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, Node, E> {
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
pub fn char_val<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, &str, E> {
    let char_val_chars = |x| match x {
        '\x20'..='\x21' | '\x23'..='\x7E' => true,
        _ => false,
    };

    let (input, (_, val, _)) = tuple((DQUOTE, take_while(char_val_chars), DQUOTE))(input)?;

    Ok((input, val))
}

/// num-val = "%" (bin-val / dec-val / hex-val)
pub fn num_val<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, NumVal, E> {
    let parser = tuple((char('%'), alt((bin_val, dec_val, hex_val))));

    let (input, (_, range)) = parser(input)?;

    Ok((input, range))
}

/// bin-val = "b" 1*BIT [ 1*("." 1*BIT) / ("-" 1*BIT) ]
///            ; series of concatenated bit values
///            ;  or single ONEOF range
pub fn bin_val<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, NumVal, E> {
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
            NumVal::Terminal(all)
        }),
        map(tuple((char('-'), many1(BIT))), |(_, end)| {
            NumVal::Range(
                start,
                u32::from_str_radix(&end.into_iter().collect::<String>(), 2)
                    .expect("should never happen"),
            )
        }),
    )))(input)?;

    if let Some(r) = compl {
        Ok((input, r))
    } else {
        Ok((input, NumVal::Terminal(vec![start])))
    }
}

/// dec-val = "d" 1*DIGIT [ 1*("." 1*DIGIT) / ("-" 1*DIGIT) ]
pub fn dec_val<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, NumVal, E> {
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
            NumVal::Terminal(all)
        }),
        map(tuple((char('-'), many1(DIGIT))), |(_, end)| {
            NumVal::Range(
                start,
                u32::from_str_radix(&end.into_iter().collect::<String>(), 10).unwrap(),
            )
        }),
    )))(input)?;

    if let Some(r) = compl {
        Ok((input, r))
    } else {
        Ok((input, NumVal::Terminal(vec![start])))
    }
}

/// hex-val = "x" 1*HEXDIG [ 1*("." 1*HEXDIG) / ("-" 1*HEXDIG) ]
pub fn hex_val<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, NumVal, E> {
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
            NumVal::Terminal(all)
        }),
        map(tuple((char('-'), many1(HEXDIG))), |(_, end)| {
            NumVal::Range(
                start,
                u32::from_str_radix(&end.into_iter().collect::<String>(), 16).unwrap(),
            )
        }),
    )))(input)?;

    if let Some(r) = compl {
        Ok((input, r))
    } else {
        Ok((input, NumVal::Terminal(vec![start])))
    }
}

/// prose-val = "<" *(%x20-3D / %x3F-7E) ">"
///             ; bracketed string of SP and VCHAR without angles
///             ; prose description, to be used as last resort
pub fn prose_val<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, &str, E> {
    let prose_val_chars = |x| match x {
        '\x20'..='\x3D' | '\x3F'..='\x7E' => true,
        _ => false,
    };

    let (input, (_, val, _)) = tuple((char('<'), take_while(prose_val_chars), char('>')))(input)?;

    Ok((input, val))
}

#[cfg(test)]
mod tests {
    use super::*;
    //use crate::types::*;
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
                6 => Node::CharVal(name), // TODO
                7 => Node::NumVal(NumVal::arbitrary(g)),
                8 => Node::ProseVal(name), // TODO
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

    impl Arbitrary for NumVal {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            use super::NumVal::*;
            [
                Terminal(Vec::<u32>::arbitrary(g)),
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
            ("a = A\n", Rule::new("a", Node::Rulename("A".into()))),
            (
                "B = A / B\n",
                Rule::new(
                    "B",
                    Node::Alternation(vec![Node::Rulename("A".into()), Node::Rulename("B".into())]),
                ),
            ),
            (
                "c = (A / B)\n",
                Rule::new(
                    "c",
                    Node::Group(Box::new(Node::Alternation(vec![
                        Node::Rulename("A".into()),
                        Node::Rulename("B".into()),
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
                        Node::Rulename("A".into()),
                        Node::Rulename("B".into()),
                    ]))))),
                ),
            ),
            (
                "a = 0*15\"-\"\n",
                Rule::new(
                    "a",
                    Node::Repetition(Repetition::new(
                        Repeat::with(Some(0), Some(15)),
                        Node::CharVal("-".into()),
                    )),
                ),
            ),
            (
                "a = *\"-\"\n",
                Rule::new(
                    "a",
                    Node::Repetition(Repetition::new(
                        Repeat::unbounded(),
                        Node::CharVal("-".into()),
                    )),
                ),
            ),
        ];

        for (test, expected) in tests {
            let (remaining, got) = rule::<VerboseError<&str>>(test).unwrap();
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
        let expected = NumVal::Terminal(vec![0x00, 0x0A, 0xff]);
        let got1 = num_val::<VerboseError<&str>>("%b0.1010.11111111");
        let got2 = num_val::<VerboseError<&str>>("%d0.10.255");
        let got3 = num_val::<VerboseError<&str>>("%x0.A.ff");
        assert_eq!(expected, got1.unwrap().1);
        assert_eq!(expected, got2.unwrap().1);
        assert_eq!(expected, got3.unwrap().1);
    }

    #[test]
    fn test_bin_val() {
        let expected = NumVal::Terminal(vec![0x00, 0x03, 0xff]);
        let got = bin_val::<VerboseError<&str>>("b00.11.11111111");
        assert_eq!(expected, got.unwrap().1);

        let expected = NumVal::Range(0, 255);
        let got = bin_val::<VerboseError<&str>>("b00-11111111");
        assert_eq!(expected, got.unwrap().1)
    }

    #[test]
    fn test_dec_val() {
        let expected = NumVal::Terminal(vec![0, 42, 255]);
        let got = dec_val::<VerboseError<&str>>("d0.42.255");
        assert_eq!(expected, got.unwrap().1);

        let expected = NumVal::Range(0, 255);
        let got = dec_val::<VerboseError<&str>>("d0-255");
        assert_eq!(expected, got.unwrap().1)
    }

    #[test]
    fn test_hex_val() {
        let expected = NumVal::Terminal(vec![0xCA, 0xFF, 0xEE]);
        let got = hex_val::<VerboseError<&str>>("xCA.FF.EE");
        assert_eq!(expected, got.unwrap().1);

        let expected = NumVal::Range(0, 255);
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
            (
                "a =/ A\n",
                Rule::incremental("a", Node::Rulename("A".into())),
            ),
            (
                "B =/ A / B\n",
                Rule::incremental(
                    "B",
                    Node::Alternation(vec![Node::Rulename("A".into()), Node::Rulename("B".into())]),
                ),
            ),
        ];

        for (test, expected) in tests {
            let (remaining, got) = rule::<VerboseError<&str>>(test).unwrap();
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

        if let Err(_) = rule::<VerboseError<&str>>(&printed) {
            println!("# Found interesting rule:");
            println!("{}", test);
            println!("{:#?}", test);
        }
    }

    #[test]
    fn test_repetition_repetition() {
        // FIXME: This test can not fail currently.
        let rule = Rule::new(
            "rule",
            Node::Repetition(Repetition::new(
                Repeat::with(Some(1), Some(12)),
                Node::Repetition(Repetition::new(
                    Repeat::with(Some(1), Some(2)),
                    Node::ProseVal("test".into()),
                )),
            )),
        );
        println!("{}", rule);
    }
}
