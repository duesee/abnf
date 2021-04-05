//! This module contains error related structs.
//!
//! Currently, this module defines `ParsingError`, whos only purpose is to be displayed to a user.
//!
//! # Example
//!
//! This code ...
//!
//! ```
//! use abnf::rule;
//!
//! let error = rule("bad-rule = *a]").unwrap_err();
//!
//! println!("{}", error);
//! ```
//!
//! ... will print ...
//!
//! ```text
//! 0: at line 0, in Tag:
//! bad-rule = *a]
//!              ^
//!
//! 1: at line 0, in Alt:
//! bad-rule = *a]
//!              ^
//!
//! 2: at line 0, in Alt:
//! bad-rule = *a]
//!              ^
//! ```
//!
//! **Note**: `ParsingError` is in fact just `Nom`'s `VerboseError` in disguise.
//! Currently, it is a best effort solution to give a rough idea where the erroneous syntax is.

use std::{error::Error, fmt};

/// A generic parsing error.
#[derive(Debug)]
pub struct ParseError {
    pub(crate) message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.message)
    }
}

impl Error for ParseError {}
