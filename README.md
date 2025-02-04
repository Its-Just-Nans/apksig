# apksig [![crates.io version](https://img.shields.io/crates/v/apksig)](https://crates.io/crates/apksig) ![crates.io downloads](https://img.shields.io/crates/d/apksig)

- <https://docs.rs/apksig> - documentation
- <https://n4n5.dev/apksig/> - online demo
- <https://github.com/Its-Just-Nans/apksig> - repository

[![asciicast](https://asciinema.org/a/699727.svg)](https://asciinema.org/a/699727)

## Usage

For rust usage, see [./tests](./tests) for examples.

```sh
cargo install apksig


apksig myapp.apk
```

## Rust features

To use `apksign` without dependencies, or only with useful dependencies for your use case, you can disable features.

```toml
[dependencies]
apksig = { version = "0.1", default-features = false } # you want nothing
# or
apksig = { version = "0.1", default-features = false, features = ["serde", "hash"] } # you want only some features
```

See [./Cargo.toml](./Cargo.toml) for all available features and documentation.
