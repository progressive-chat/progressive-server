# Step 273 — "Clean up reqwest::Response to http::Response conversion" (Conduit `8bfaf09`)

Source: [`timokoesters/conduit@8bfaf09`](https://github.com/timokoesters/conduit/commit/8bfaf09) (2021-04)

## What changed vs step 272

| Rust change | C++ translation |
|---|---|
| Clean up reqwest::Response to http::Response conversion. HTTP client internal cleanup. | **No-op for us** — Rust reqwest internals — our httplib is different. |

## Implementation details

- Rust reqwest internals — our httplib is different.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
