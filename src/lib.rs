//! A crate for parsing ABNF definitions.
//!
//! This crate exposes two functions for now, `rulelist` and `rule`.
//! The functions are designed to cover the use case, where the complete ABNF definition is provided as a string.
//!
//! On success, both functions return `Ok(...)` with the parsed object.
//! If the ABNF definition contains a syntax error, both functions will return `Err(ParsingError)`.
//! `ParsingError` is intended to be displayed to a user and should help correcting mistakes in the
//! provided ABNF definition.
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

pub mod error;
pub mod types;

mod abnf;
mod core;

use crate::{
    abnf::{
        rule as rule_internal,
        rulelist as rulelist_internal,
    },
    types::Rule,
    error::ParsingError,
};

use nom::{
    combinator::all_consuming,
    error::{convert_error, VerboseError},
};

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
pub fn rulelist(input: &str) -> Result<Vec<Rule>, ParsingError> {
    match all_consuming(rulelist_internal::<VerboseError<&str>>)(input) {
        Ok((remaining, rules)) => {
            assert!(remaining.is_empty());
            Ok(rules)
        }
        Err(error) => match error {
            nom::Err::Incomplete(_) => unreachable!(),
            nom::Err::Error(e) | nom::Err::Failure(e) => Err(ParsingError { message: convert_error(input, e) }),
        }
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
pub fn rule(input: &str) -> Result<Rule, ParsingError> {
    match all_consuming(rule_internal::<VerboseError<&str>>)(input) {
        Ok((remaining, rule)) => {
            assert!(remaining.is_empty());
            Ok(rule)
        }
        Err(error) => match error {
            nom::Err::Incomplete(_) => unreachable!(),
            nom::Err::Error(e) | nom::Err::Failure(e) => Err(ParsingError { message: convert_error(input, e) }),
        }
    }
}

#[cfg(test)]
mod test {
    use super::rulelist;

    #[test]
    fn test_error_handling() {
        let data = "a = *b\n\n\nb = *x";
        let error = rulelist(data).unwrap_err();
        println!("{}", error);
    }
}