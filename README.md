# ABNF
A nom-based ABNF parser.

## Example

Input

```
rulelist   =   1*( rule / (*WSP c-nl) )
                ; this is
                ; a rule
```

Output

```
// std::fmt::Display
rulelist = 1*(rule / (*WSP c-nl))

// std::fmt::Debug
Rule {
    name: "rulelist",
    node: Repetition(
        Repetition {
            repeat: Repeat {
                min: Some(
                    1,
                ),
                max: None,
            },
            node: Group(
                Alternation(
                    [
                        Rulename(
                            "rule",
                        ),
                        Group(
                            Concatenation(
                                [
                                    Repetition(
                                        Repetition {
                                            repeat: Repeat {
                                                min: None,
                                                max: None,
                                            },
                                            node: Rulename(
                                                "WSP",
                                            ),
                                        },
                                    ),
                                    Rulename(
                                        "c-nl",
                                    ),
                                ],
                            ),
                        ),
                    ],
                ),
            ),
        },
    ),
    definition: Basic,
}
```
