//! ```rust
//! use abnf::abnf::rulelist_comp;
//!
//! // Nom is a streaming parser. Thus, when handling finite input,
//! // use functions with _comp suffix to avoid `Err::Incomplete`.
//! let res = rulelist_comp(b"rule = A / B\n\n").unwrap().1;
//!
//! for rule in &res {
//!     println!("{}\n", rule);
//! }
//! ```

#[macro_use]
extern crate nom;

pub mod abnf;
pub mod core;
