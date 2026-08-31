# Step 71 — "Update ruma version" (Conduit `1e8fbd8`)

Source: [`timokoesters/conduit@1e8fbd8`](https://github.com/timokoesters/conduit/commit/1e8fbd8) (2020-09)

## What changed vs step 70

| Rust change | C++ translation |
|---|---|
| Updates the ruma crate to a new version. 33 files changed, mostly type adaptations. | **Skipped** — ruma is a Rust crate we don't use. |

## Implementation details

- **Skipped** — ruma is a Rust crate we don't use.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
