# CHANGELOG

## Unreleased

- hardening lib with `clippy::indexing_slicing` checks
- remove `real_main` from `lib.rs` (all in `main.rs` instead)

## `0.2.8`

- rename `find_oecd` to `find_eocd` (typo)
- implement u32 serialization for `Algorithms` enum

## `0.2.7`

- change function from `&mut File` to `<R: Read + Seek>` for more flexibility (use a `Cursor` for `Vec<u8>`)
- add a test to digest a raw apk (without the APK Signing block)
