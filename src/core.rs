#![allow(non_snake_case)]

//!
//! Parsing of ABNF Core Rules
//!
//! See https://tools.ietf.org/html/rfc5234#appendix-B.1
//!

use nom::branch::alt;
use nom::bytes::complete::tag;
use nom::character::complete::{char, one_of};
use nom::combinator::map;
use nom::combinator::recognize;
use nom::error::{ErrorKind, ParseError};
use nom::multi::many0;
use nom::sequence::tuple;
use nom::{Err, IResult};

pub fn one<'a, E: ParseError<&'a str>, F: Fn(char) -> bool>(
    input: &'a str,
    f: F,
) -> IResult<&'a str, char, E> {
    if input.is_empty() {
        return Err(Err::Error(ParseError::from_error_kind(
            input,
            ErrorKind::OneOf,
        )));
    }

    let mut chars = input.chars();
    let first = chars.nth(0).unwrap();

    if f(first) {
        Ok((chars.as_str(), first))
    } else {
        Err(Err::Error(ParseError::from_error_kind(
            input,
            ErrorKind::OneOf,
        )))
    }
}

/// ALPHA = %x41-5A / %x61-7A ; A-Z / a-z
pub fn ALPHA<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, char, E> {
    one(input, is_ALPHA)
}

pub fn is_ALPHA(c: char) -> bool {
    c.is_ascii_alphabetic()
}

/// BIT = "0" / "1"
pub fn BIT<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, char, E> {
    one_of("01")(input)
}

/// CHAR = %x01-7F ; any 7-bit US-ASCII character, excluding NUL
pub fn CHAR<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, char, E> {
    one(input, is_CHAR)
}

pub fn is_CHAR(c: char) -> bool {
    match c {
        '\x01'..='\x7F' => true,
        _ => false,
    }
}

/// CR = %x0D ; carriage return
pub fn CR<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, char, E> {
    char('\r')(input)
}

/// CRLF = CR LF ; Internet standard newline
pub fn CRLF<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, &str, E> {
    // This function accepts both, LF and CRLF
    // FIXME: ?
    alt((tag("\r\n"), tag("\n")))(input)
}

/// CTL = %x00-1F / %x7F ; controls
pub fn CTL<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, char, E> {
    one(input, is_CTL)
}

pub fn is_CTL(c: char) -> bool {
    match c {
        '\x00'..='\x1F' | '\x7F' => true,
        _ => false,
    }
}

/// DIGIT = %x30-39 ; 0-9
pub fn DIGIT<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, char, E> {
    one_of("0123456789")(input)
}

pub fn is_DIGIT(c: char) -> bool {
    c.is_ascii_digit()
}

/// DQUOTE = %x22 ; " (Double Quote)
pub fn DQUOTE<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, char, E> {
    char('"')(input)
}

/// HEXDIG = DIGIT / "A" / "B" / "C" / "D" / "E" / "F"
pub fn HEXDIG<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, char, E> {
    one(input, is_HEXDIG)
}

pub fn is_HEXDIG(c: char) -> bool {
    c.is_ascii_hexdigit()
}

/// HTAB = %x09 ; horizontal tab
pub fn HTAB<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, char, E> {
    char('\t')(input)
}

/// LF = %x0A ; linefeed
pub fn LF<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, char, E> {
    char('\n')(input)
}

/// LWSP = *(WSP / CRLF WSP)
///         ; Use of this linear-white-space rule
///         ;  permits lines containing only white
///         ;  space that are no longer legal in
///         ;  mail headers and have caused
///         ;  interoperability problems in other
///         ;  contexts.
///         ; Do not use when defining mail
///         ;  headers and use with caution in
///         ;  other contexts.
pub fn LWSP<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, &str, E> {
    let parser = recognize(many0(alt((recognize(WSP), recognize(tuple((CRLF, WSP)))))));

    parser(input)
}

/// OCTET = %x00-FF ; 8 bits of data
pub fn OCTET(input: &[u8]) -> IResult<&[u8], &[u8]> {
    if input.is_empty() {
        Err(Err::Error((input, nom::error::ErrorKind::Char)))
    } else {
        Ok((&input[1..], &input[0..1]))
    }
}

/// SP = %x20
pub fn SP<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, char, E> {
    char(' ')(input)
}

/// VCHAR = %x21-7E ; visible (printing) characters
pub fn VCHAR<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, char, E> {
    one(input, is_VCHAR)
}

pub fn is_VCHAR(c: char) -> bool {
    match c {
        '\x21'..='\x7E' => true,
        _ => false,
    }
}

/// WSP = SP / HTAB ; white space
pub fn WSP<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, char, E> {
    alt((SP, HTAB))(input)
}

pub fn is_WSP(c: char) -> bool {
    match c {
        '\x20' | '\x09' => true,
        _ => false,
    }
}

/*
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_BIT() {
        assert_eq!(BIT("100"), Ok(("00", '1')));
        assert_eq!(BIT("010"), Ok(("10", '0')));
        assert!(BIT("").is_err());
        assert!(BIT("/").is_err());
        assert!(BIT("2").is_err());
    }

    #[test]
    fn test_HEXDIG() {
        assert_eq!(HEXDIG("FaA"), Ok(("aA", 'F')));

        assert_eq!(HEXDIG("0aA"), Ok(("aA", '0')));

        assert!(HEXDIG("").is_err());
        assert!(HEXDIG("/").is_err());
        assert!(HEXDIG(":").is_err());
        assert!(HEXDIG("`").is_err());
        assert!(HEXDIG("g").is_err());
        assert!(HEXDIG("@").is_err());
        assert!(HEXDIG("G").is_err());
    }

}
*/
