# Step 733 — "Enable support for room v11" (Conduit `9646439`)

Source: [`timokoesters/conduit@9646439`](https://github.com/timokoesters/conduit/commit/9646439) (2023-12)

## What changed vs step 732

| Rust change | C++ translation |
|---|---|
| Enable support for room v11. Room version 11 support. 1 file changed. | **Translated** — Follows step 565/566 (v9/v10). Room v11 adds new features. |

## Implementation details

- Follows step 565/566 (v9/v10). Room v11 adds new features.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
