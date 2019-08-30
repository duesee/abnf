#![allow(non_snake_case)]

//!
//! Parsing of ABNF Core Rules
//!
//! See https://tools.ietf.org/html/rfc5234#appendix-B.1
//!

use nom::branch::alt;
use nom::bytes::complete::tag;
use nom::character::complete::char;
use nom::combinator::map;
use nom::multi::many0;
use nom::sequence::tuple;
use nom::{Err, IResult};

/// ALPHA = %x41-5A / %x61-7A ; A-Z / a-z
pub fn ALPHA(i: &[u8]) -> IResult<&[u8], char> {
    if i.is_empty() {
        Err(Err::Error((i, nom::error::ErrorKind::Char)))
    } else if is_ALPHA(i[0]) {
        Ok((&i[1..], i[0] as char))
    } else {
        Err(Err::Error((i, nom::error::ErrorKind::Char)))
    }
}

pub fn is_ALPHA(i: u8) -> bool {
    match i as char {
        'a'..='z' | 'A'..='Z' => true,
        _ => false,
    }
}

/// BIT = "0" / "1"
pub fn BIT(input: &[u8]) -> IResult<&[u8], char> {
    nom::character::complete::one_of("01")(input)
}

/// CHAR = %x01-7F ; any 7-bit US-ASCII character, excluding NUL
pub fn CHAR(i: &[u8]) -> IResult<&[u8], &[u8]> {
    if i.is_empty() {
        Err(Err::Error((i, nom::error::ErrorKind::Char)))
    } else if is_CHAR(i[0]) {
        Ok((&i[1..], &i[0..1]))
    } else {
        Err(Err::Error((i, nom::error::ErrorKind::Char)))
    }
}

pub fn is_CHAR(i: u8) -> bool {
    match i {
        0x01..=0x7F => true,
        _ => false,
    }
}

/// CR = %x0D ; carriage return
pub fn CR(input: &[u8]) -> IResult<&[u8], char> {
    char('\r')(input)
}

/// CRLF = CR LF ; Internet standard newline
pub fn CRLF(input: &[u8]) -> IResult<&[u8], &[u8]> {
    alt((tag("\r\n"), tag("\n")))(input) // FIXME: ?
}

/// CTL = %x00-1F / %x7F ; controls
pub fn CTL(i: &[u8]) -> IResult<&[u8], &[u8]> {
    if i.is_empty() {
        Err(Err::Error((i, nom::error::ErrorKind::Char)))
    } else if is_CTL(i[0]) {
        Ok((&i[1..], &i[0..1]))
    } else {
        Err(Err::Error((i, nom::error::ErrorKind::Char)))
    }
}

pub fn is_CTL(i: u8) -> bool {
    match i {
        0x00..=0x1F | 0x7F => true,
        _ => false,
    }
}

/// DIGIT = %x30-39 ; 0-9
pub fn DIGIT(input: &[u8]) -> IResult<&[u8], char> {
    nom::character::complete::one_of("0123456789")(input)
}

pub fn is_DIGIT(i: u8) -> bool {
    match i {
        b'0'..=b'9' => true,
        _ => false,
    }
}

/// DQUOTE = %x22 ; " (Double Quote)
pub fn DQUOTE(input: &[u8]) -> IResult<&[u8], char> {
    char('"')(input)
}

/// HEXDIG = DIGIT / "A" / "B" / "C" / "D" / "E" / "F"
pub fn HEXDIG(input: &[u8]) -> IResult<&[u8], char> {
    nom::character::complete::one_of("0123456789abcdefABCDEF")(input)
}

pub fn is_HEXDIG(i: u8) -> bool {
    match i {
        b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' => true,
        _ => false,
    }
}

/// HTAB = %x09 ; horizontal tab
pub fn HTAB(input: &[u8]) -> IResult<&[u8], char> {
    char('\t')(input)
}

/// LF = %x0A ; linefeed
pub fn LF(input: &[u8]) -> IResult<&[u8], char> {
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
pub fn LWSP(input: &[u8]) -> IResult<&[u8], Vec<Vec<u8>>> {
    let parser = many0(alt((
        map(WSP, |c| vec![c as u8]),
        map(tuple((CRLF, WSP)), |(crlf, wsp)| {
            let mut tmp = Vec::new();
            tmp.extend(crlf);
            tmp.push(wsp as u8);
            tmp
        }),
    )));

    parser(input)
}

/// OCTET = %x00-FF ; 8 bits of data
pub fn OCTET(i: &[u8]) -> IResult<&[u8], &[u8]> {
    if i.is_empty() {
        Err(Err::Error((i, nom::error::ErrorKind::Char)))
    } else {
        Ok((&i[1..], &i[0..1]))
    }
}

/// SP = %x20
pub fn SP(input: &[u8]) -> IResult<&[u8], char> {
    char(' ')(input)
}

/// VCHAR = %x21-7E ; visible (printing) characters
pub fn VCHAR(i: &[u8]) -> IResult<&[u8], char> {
    if i.is_empty() {
        Err(Err::Error((i, nom::error::ErrorKind::Char)))
    } else if is_VCHAR(i[0]) {
        Ok((&i[1..], i[0] as char))
    } else {
        Err(Err::Error((i, nom::error::ErrorKind::Char)))
    }
}

pub fn is_VCHAR(i: u8) -> bool {
    match i {
        0x21..=0x7E => true,
        _ => false,
    }
}

/// WSP = SP / HTAB ; white space
pub fn WSP(input: &[u8]) -> IResult<&[u8], char> {
    alt((SP, HTAB))(input)
}

pub fn is_WSP(i: u8) -> bool {
    match i {
        0x20 | 0x09 => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_BIT() {
        assert_eq!(BIT(b"100"), Ok((&[b'0', b'0'][..], '1')));
        assert_eq!(BIT(b"010"), Ok((&[b'1', b'0'][..], '0')));
        assert!(BIT(b"").is_err());
        assert!(BIT(b"/").is_err());
        assert!(BIT(b"2").is_err());
    }

    #[test]
    fn test_HEXDIG() {
        assert_eq!(HEXDIG(b"FaA"), Ok((&[b'a', b'A'][..], 'F')));

        assert_eq!(HEXDIG(b"0aA"), Ok((&[b'a', b'A'][..], '0')));

        assert!(HEXDIG(b"").is_err());
        assert!(HEXDIG(b"/").is_err());
        assert!(HEXDIG(b":").is_err());
        assert!(HEXDIG(b"`").is_err());
        assert!(HEXDIG(b"g").is_err());
        assert!(HEXDIG(b"@").is_err());
        assert!(HEXDIG(b"G").is_err());
    }

}
