# ABNF
A nom-based ABNF parser.

# Status
Not thoroughly tested, but works with arguably complex ABNFs.

# Branches

There are some experimental branches. The `with_generic_node` branch uses an enum...

```Rust
enum Node {
    Alternation(Vec<Node>>),
    Concatenation(Vec<Node>>),
    ...
}
```

...which may be more suitable when implementing transformations.

The `master` branch is a direct transformation of RFC 5234 to code.
