<p align="right">
  <a href="https://travis-ci.org/duesee/abnf"><img src="https://travis-ci.org/duesee/abnf.svg?branch=master" title="travis-ci.org"/></a>
  <a href="https://docs.rs/abnf"><img src="https://img.shields.io/badge/documentation-docs.rs-informational" title="docs.rs"/></a>
</p>

# ABNF

A parser for ABNF based on nom 6.

## Example

The following code

```rust
use abnf::rulelist;

// Note: mind the trailing newline!
match rulelist("a = b / c\nc = *(d e)\n") {
    Ok(rules) => println!("{:#?}", rules),
    Err(error) => eprintln!("{}", error),
}
```

outputs

```rust
[
    Rule {
        name: "a",
        node: Alternatives(
            [
                Rulename(
                    "b",
                ),
                Rulename(
                    "c",
                ),
            ],
        ),
        kind: Basic,
    },
    Rule {
        name: "c",
        node: Repetition {
            repeat: Variable {
                min: None,
                max: None,
            },
            node: Group(
                Concatenation(
                    [
                        Rulename(
                            "d",
                        ),
                        Rulename(
                            "e",
                        ),
                    ],
                ),
            ),
        },
        kind: Basic,
    },
]
```

You can also use the provided example to parse and `Debug`-print any ABNF file.

```sh
cargo run --example=example examples/assets/abnf.abnf
```

# License

This crate is dual-licensed under Apache 2.0 and MIT terms.
