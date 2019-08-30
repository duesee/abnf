//! ```
//! use abnf::rulelist;
//!
//! let (remaining, rules) = rulelist(b"rule = A / B / C\n").unwrap();
//!
//! for rule in &rules {
//!     println!("[!] {:#?}\n", rule);
//! }
//!
//! println!("---------------\n{}", String::from_utf8_lossy(remaining));
//! ```

mod abnf;
pub mod core;
mod types;

pub use crate::abnf::*;
pub use crate::types::*;
