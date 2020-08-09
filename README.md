<p align="right">
  <a href="https://travis-ci.org/duesee/abnf"><img src="https://travis-ci.org/duesee/abnf.svg?branch=master" title="travis-ci.org"/></a>
  <a href="https://docs.rs/abnf"><img src="https://img.shields.io/badge/documentation-docs.rs-informational" title="docs.rs"/></a>
</p>

# ABNF

A parser for ABNF based on nom 5.

## Example

```rust
use abnf::rulelist;

match rulelist("a = b / c\nc = *(d e)\n") {
    Ok(rules) => println!("{:#?}", rules),
    Err(error) => eprintln!("{}", error),
}
```

## Output

```
[
    Rule {
        name: "a",
        node: Alternation(
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
        node: Repetition(
            Repetition {
                repeat: Repeat {
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
        ),
        kind: Basic,
    },
]
```

# License

This crate is dual-licensed under Apache 2.0 and MIT terms.
