[![CI](https://github.com/duesee/abnf/actions/workflows/ci.yml/badge.svg)](https://github.com/duesee/abnf/actions/workflows/ci.yml)
[![Scheduled](https://github.com/duesee/abnf/actions/workflows/scheduled.yml/badge.svg)](https://github.com/duesee/abnf/actions/workflows/scheduled.yml)
[![docs](https://docs.rs/abnf/badge.svg)](https://docs.rs/abnf)

# ABNF

A parser for ABNF based on nom 7.

## Example

The ABNF input ...

```abnf
a = b / c
c = *(d e)
```

... is parsed with ...

```rust
use abnf::rulelist;

// Note: mind the trailing newline!
match rulelist("a = b / c\nc = *(d e)\n") {
    Ok(rules) => println!("{:#?}", rules),
    Err(error) => eprintln!("{}", error),
}
```

... into ...

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

You can use the provided example to parse and `Debug`-print any ABNF file:

```sh
cargo run --example=example examples/assets/abnf.abnf
```

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
