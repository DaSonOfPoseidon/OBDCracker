# Development

## Crate layout

| Crate | Role |
|---|---|
| `obdcracker` | Facade for importers: re-exports the crates below (`sim` behind a feature) |
| `obdcracker-core` | Pure `no_std` codecs: CAN, ISO-TP, VW TP2.0, OBD-II, UDS, KWP2000 |
| `obdcracker-safety` | Tiered policy and `Approved` |
| `obdcracker-transport` | `Transport` trait and adapter backends |
| `obdcracker-profile` | Vehicle profiles: module addresses, addressing, protocol and DIDs, as TOML data |
| `obdcracker-sim` | Simulated ECUs for tests: a profile plus a fixture of what each module answers (built in: `a7`) |
| `obdcracker-cli` | The `obdcracker` command-line tool |

## Checks

```sh
cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test --all-features
cargo build -p obdcracker-core --target thumbv7em-none-eabihf  # obdcracker-core must stay no_std
```

You need either a local `rustup` (the version is pinned in `rust-toolchain.toml`) or Docker: `scripts/cargo.sh <args>` runs
cargo in a container.

The Rust examples in `README.md` and [`library.md`](library.md) are compiled as doctests of the `obdcracker` crate.

See [CONTRIBUTING](CONTRIBUTING.md) for how changes land, and [pitfalls](pitfalls.md) before making one.
