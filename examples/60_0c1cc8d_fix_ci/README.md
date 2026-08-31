# Step 60 — "Fix CI" (Conduit `0c1cc8d`)

Source: [`timokoesters/conduit@0c1cc8d`](https://github.com/timokoesters/conduit/commit/0c1cc8d) (2020-08)

## What changed vs step 59

| Rust change | C++ translation |
|---|---|
| Fixes the CI configuration. | **Skipped** — pure CI infrastructure change. |

## Implementation details

- **Skipped** — pure CI infrastructure change.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
