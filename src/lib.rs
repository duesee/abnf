//! ```rust
//! use abnf::abnf::rulelist;
//!
//! let (remaining, rules) = rulelist(b"rule = A / B / C\n").unwrap();
//!
//! for rule in &rules {
//!     println!("[!] {}\n", rule);
//! }
//!
//! println!("---------------\n{}", String::from_utf8_lossy(remaining));
//! ```

pub mod abnf;
pub mod core;
