#![allow(non_snake_case)]

use nom::{Context, Err, ErrorKind, IResult, Needed};

/// ALPHA = %x41-5A / %x61-7A ; A-Z / a-z
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

/// BIT = "0" / "1"
named!(pub BIT<char>, do_parse!(
    bit: one_of!("01") >> (bit)
));

/// CHAR = %x01-7F ; any 7-bit US-ASCII character, excluding NUL
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

/// CR = %x0D ; carriage return
named!(pub CR<char>,
    char!('\r')
);

/// CRLF = CR LF ; Internet standard newline
named!(pub CRLF<&[u8]>,
    alt!(tag!("\r\n") | tag!("\n")) // TODO: Fixme?
);

/// CTL = %x00-1F / %x7F ; controls
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

/// DIGIT = %x30-39 ; 0-9
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

/// DQUOTE = %x22 ; " (Double Quote)
named!(pub DQUOTE<char>,
    char!('"')
);

/// HEXDIG = DIGIT / "A" / "B" / "C" / "D" / "E" / "F"
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

/// HTAB = %x09 ; horizontal tab
named!(pub HTAB<char>,
    char!('\x09')
);

/// LF = %x0A ; linefeed
named!(pub LF<char>,
    char!('\n')
);

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
named!(pub LWSP<Vec<Vec<u8>>>, do_parse!(
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

/// OCTET = %x00-FF ; 8 bits of data
pub fn OCTET(i:&[u8]) -> IResult<&[u8], &[u8]>{
    if i.len() < 1 {
        Err(Err::Incomplete(Needed::Size(1)))
    } else {
        Ok((&i[1..], &i[0..1]))
    }
}

/// SP = %x20
named!(pub SP<char>,
    char!(' ')
);

/// VCHAR = %x21-7E ; visible (printing) characters
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

/// WSP = SP / HTAB ; white space
named!(pub WSP<char>, do_parse!(
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
