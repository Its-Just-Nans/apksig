# CHANGELOG

## `0.2.9`

- hardening lib with `clippy::indexing_slicing` checks
- remove `real_main` from `lib.rs` (all in `main.rs` instead)
- move zip utilities to `zip` module
- add `Apk::digest()` method
- add `clippy::clippy::print_stdout` to forbid `println!` in lib - interestingly, `cargo clippy` does not catch `println!` in macros
- add `Apk::get_raw_apk()` method

## `0.2.8`

- rename `find_oecd` to `find_eocd` (typo)
- implement u32 serialization for `Algorithms` enum

## `0.2.7`

- change function from `&mut File` to `<R: Read + Seek>` for more flexibility (use a `Cursor` for `Vec<u8>`)
- add a test to digest a raw apk (without the APK Signing block)

## `0.2.6`

- fix the lib of `0.2.5` <https://github.com/Its-Just-Nans/apksig/commit/214d0df27b66128a92d3cffbb854492b299d1d0c>

## `0.2.5`

- yanked because does not compile because of feature conflict

## `0.2.4`

- forgor to publish (again - rip)

## `0.2.3`

- yanked because contains a git (sub) repository and apk

## `0.2.2`

- yanked because contains a git (sub) repository and apk

## `0.2.1`

- forgor to publish
