# Step 742 — "fix `cargo check` lints" (Conduit `92c5b6b`)

Source: [`timokoesters/conduit@92c5b6b`](https://github.com/timokoesters/conduit/commit/92c5b6b) (2024-01)

## What changed vs step 741

| Rust change | C++ translation |
|---|---|
| Fix `cargo check` lints. Rust lint fixes. 4 files changed. | **No-op for us** — Rust lints — our C++ uses clang-tidy. |

## Implementation details

- Rust lints — our C++ uses clang-tidy.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
