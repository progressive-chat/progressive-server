# Step 124 — "First version of cargo-deb packaging setup" (Conduit `79692db`)

Source: [`timokoesters/conduit@79692db`](https://github.com/timokoesters/conduit/commit/79692db) (2020-11)

## What changed vs step 123

| Rust change | C++ translation |
|---|---|
| First version of cargo-deb packaging setup (for Debian package distribution). | **Skipped** — Pure packaging/distribution change. |

## Implementation details

- Pure packaging/distribution change.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
