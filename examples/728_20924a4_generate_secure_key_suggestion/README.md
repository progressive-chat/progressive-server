# Step 728 — "Suggestion on how to generate a secure key" (Conduit `20924a4`)

Source: [`timokoesters/conduit@20924a4`](https://github.com/timokoesters/conduit/commit/20924a4) (2023-08)

## What changed vs step 727

| Rust change | C++ translation |
|---|---|
| Suggestion on how to generate a secure key. Security documentation. | **Skipped** — Documentation only. |

## Implementation details

- Documentation only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
