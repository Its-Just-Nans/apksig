# apksig [![crates.io version](https://img.shields.io/crates/v/apksig)](https://crates.io/crates/apksig) ![crates.io downloads](https://img.shields.io/crates/d/apksig) [![docs.rs](https://img.shields.io/docsrs/apksig)](https://docs.rs/apksig)

- <https://docs.rs/apksig> - documentation
- <https://n4n5.dev/apksig/> - online demo
- <https://github.com/Its-Just-Nans/apksig> - repository

[![asciicast](https://asciinema.org/a/699727.svg)](https://asciinema.org/a/699727)

## Usage

For rust usage, see <https://docs.rs/apksig> or [./tests](./tests) for examples.

```sh
cargo install apksig
# then use with
apksig myapp.apk
```

## Rust features

To use `apksign` without dependencies, or only with useful dependencies for your use case, you can disable features.

```toml
[dependencies]
apksig = { version = "xx", default-features = false } # you want nothing
# or if you want only some features
apksig = { version = "xx", default-features = false, features = ["serde", "hash"] }
```

See [./Cargo.toml](./Cargo.toml) for all available features and documentation.

## Tests

Coverage is available at <https://n4n5.dev/apksig/coverage/>.

## LICENSE

- [MIT](./LICENSE)
