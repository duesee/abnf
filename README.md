<p align="right">
  <a href="https://docs.rs/abnf"><img src="https://img.shields.io/badge/documentation-docs.rs-informational" title="docs.rs"></a>
</p>

# ABNF

A parser for ABNF based on nom 5.

## Example

This ...

```rust
use abnf::rulelist;

match rulelist("a = b / c\nc = *(d e)\n") {
    Ok(rules) => println!("{:#?}", rules),
    Err(error) => eprintln!("{}", error),
}
```
... prints ...

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
