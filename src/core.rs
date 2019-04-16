#![allow(non_snake_case)]

//!
//! Parsing of ABNF Core Rules
//!
//! See https://tools.ietf.org/html/rfc5234#appendix-B.1
//!

//
// TODO: can we replace nom's
//   named_attr!(#[doc = ""], ...
// with something less distracting? We should document public functions,
// but currently nom's syntax is really hard to read in the source code.
//

use nom::{Context, Err, ErrorKind, IResult, Needed};

/// ```text
/// ALPHA = %x41-5A / %x61-7A
///          ; A-Z / a-z
/// ```
pub fn ALPHA(i:&[u8]) -> IResult<&[u8], char> {
    if i.len() < 1 {
        Err(Err::Incomplete(Needed::Size(1)))
    } else {
        match i[0] as char {
            'a' ..= 'z' | 'A' ..= 'Z' => {
                Ok((&i[1..], i[0] as char))
            }
            _ => {
                let e:ErrorKind<u32> = ErrorKind::Tag;
                Err(Err::Error(Context::Code(i, e)))
            }
        }
    }
}

named_attr!(#[doc = r#"
```text
BIT = "0" / "1"
```
"#], pub BIT<char>, do_parse!(
    bit: one_of!("01") >> (bit)
));

/// ```text
/// CHAR = %x01-7F
///         ; any 7-bit US-ASCII character, excluding NUL
/// ```
pub fn CHAR(i:&[u8]) -> IResult<&[u8], &[u8]>{
    if i.len() < 1 {
        Err(Err::Incomplete(Needed::Size(1)))
    } else {
        match i[0] {
            0x01 ..= 0x7F => {
                Ok((&i[1..], &i[0..1]))
            }
            _ => {
                let e:ErrorKind<u32> = ErrorKind::Tag;
                Err(Err::Error(Context::Code(i, e)))
            }
        }
    }
}

named_attr!(#[doc = r#"
```text
CR = %x0D ; carriage return
```
"#], pub CR<char>,
    char!('\r')
);

named_attr!(#[doc = r#"
```text
CRLF = CR LF ; Internet standard newline
```
"#], pub CRLF<&[u8]>,
    alt!(tag!("\r\n") | tag!("\n")) // TODO: Fixme?
);

/// ```text
/// CTL = %x00-1F / %x7F ; controls
/// ```
pub fn CTL(i:&[u8]) -> IResult<&[u8], &[u8]>{
    if i.len() < 1 {
        Err(Err::Incomplete(Needed::Size(1)))
    } else {
        match i[0] {
            0x00 ..= 0x1F | 0x7F => {
                Ok((&i[1..], &i[0..1]))
            }
            _ => {
                let e:ErrorKind<u32> = ErrorKind::Tag;
                Err(Err::Error(Context::Code(i, e)))
            }
        }
    }
}

/// ```text
/// DIGIT = %x30-39 ; 0-9
/// ```
pub fn DIGIT(i:&[u8]) -> IResult<&[u8], char> {
    if i.len() < 1 {
        Err(Err::Incomplete(Needed::Size(1)))
    } else {
        match i[0] as char {
            '0' ..= '9' => {
                Ok((&i[1..], i[0] as char))
            }
            _ => {
                let e:ErrorKind<u32> = ErrorKind::Tag;
                Err(Err::Error(Context::Code(i, e)))
            }
        }
    }
}

named_attr!(#[doc = r#"
```text
DQUOTE = %x22 ; " (Double Quote)
```
"#], pub DQUOTE<char>,
    char!('"')
);

/// ```text
/// HEXDIG = DIGIT / "A" / "B" / "C" / "D" / "E" / "F"
/// ```
pub fn HEXDIG(i:&[u8]) -> IResult<&[u8], char> {
    if i.len() < 1 {
        Err(Err::Incomplete(Needed::Size(1)))
    } else {
        match i[0] as char {
            '0' ..= '9' | 'a' ..= 'f' | 'A' ..= 'F' => {
                Ok((&i[1..], i[0] as char))
            }
            _ => {
                let e:ErrorKind<u32> = ErrorKind::Tag;
                Err(Err::Error(Context::Code(i, e)))
            }
        }
    }
}

named_attr!(#[doc = r#"
```text
HTAB = %x09 ; horizontal tab
```
"#], pub HTAB<char>,
    char!('\x09')
);

named_attr!(#[doc = r#"
```text
LF = %x0A ; linefeed
```
"#], pub LF<char>,
    char!('\n')
);

named_attr!(#[doc = r#"
```text
LWSP = *(WSP / CRLF WSP)
        ; Use of this linear-white-space rule
        ;  permits lines containing only white
        ;  space that are no longer legal in
        ;  mail headers and have caused
        ;  interoperability problems in other
        ;  contexts.
        ; Do not use when defining mail
        ;  headers and use with caution in
        ;  other contexts.
```
"#], pub LWSP<Vec<Vec<u8>>>, do_parse!(
    lwsp: many0!(alt!(
        map!(WSP, |c| vec![c as u8]) |
        map!(tuple!(CRLF, WSP), |(crlf, wsp)| {
            let mut tmp = Vec::new();
            tmp.extend(crlf);
            tmp.push(wsp as u8);
            tmp
        })
    )) >> (lwsp)
));

/// ```text
/// OCTET = %x00-FF ; 8 bits of data
/// ```
pub fn OCTET(i:&[u8]) -> IResult<&[u8], &[u8]>{
    if i.len() < 1 {
        Err(Err::Incomplete(Needed::Size(1)))
    } else {
        Ok((&i[1..], &i[0..1]))
    }
}

named_attr!(#[doc = r#"
```text
SP = %x20
```
"#], pub SP<char>,
    char!(' ')
);

/// ```text
/// VCHAR = %x21-7E ; visible (printing) characters
/// ```
pub fn VCHAR(i:&[u8]) -> IResult<&[u8], char>{
    if i.len() < 1 {
        Err(Err::Incomplete(Needed::Size(1)))
    } else {
        match i[0] {
            0x21 ..= 0x7E => {
                Ok((&i[1..], i[0] as char))
            }
            _ => {
                let e:ErrorKind<u32> = ErrorKind::Tag;
                Err(Err::Error(Context::Code(i, e)))
            }
        }
    }
}

named_attr!(#[doc = r#"
```text
WSP = SP / HTAB ; white space
```
"#], pub WSP<char>, do_parse!(
    wsp: alt!(SP | HTAB) >> (wsp)
));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_BIT() {
        assert_eq!(
            BIT(b"100"),
            Ok(
                (&['0' as u8, '0' as u8][..], '1')
            )
        );
        assert_eq!(
            BIT(b"010"),
            Ok(
                (&['1' as u8, '0' as u8][..], '0')
            )
        );
        assert!(BIT(b"").is_err());
        assert!(BIT(b"/").is_err());
        assert!(BIT(b"2").is_err());
    }

    #[test]
    fn test_HEXDIG() {
        assert_eq!(
            HEXDIG(b"FaA"),
            Ok(
                (&['a' as u8, 'A' as u8][..], 'F')
            )
        );
        
        assert_eq!(
            HEXDIG(b"0aA"),
            Ok(
                (&['a' as u8, 'A' as u8][..], '0')
            )
        );

        assert!(HEXDIG(b"").is_err());
        assert!(HEXDIG(b"/").is_err());
        assert!(HEXDIG(b":").is_err());
        assert!(HEXDIG(b"`").is_err());
        assert!(HEXDIG(b"g").is_err());
        assert!(HEXDIG(b"@").is_err());
        assert!(HEXDIG(b"G").is_err());
    }
}
