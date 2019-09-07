//! ```
//! use abnf::rulelist;
//!
//! let (remaining, rules) = rulelist("rule = A / B / C\n").unwrap();
//!
//! for rule in &rules {
//!     println!("[!] {:#?}\n", rule);
//! }
//!
//! println!("---------------\n{}", remaining);
//! ```

mod abnf;
pub mod core;
mod types;

pub use crate::abnf::*;
pub use crate::types::*;
