# Step 89 — "improvement: better logs on deserialization errors" (Conduit `a567cd8`)

Source: [`timokoesters/conduit@a567cd8`](https://github.com/timokoesters/conduit/commit/a567cd8) (2020-09)

## What changed vs step 88

| Rust change | C++ translation |
|---|---|
| Improves the logging on federation deserialization errors. Uses `error!` instead of `dbg!()`. | Our step 43 (`a567cd81d_logs`) implements better error logging in `send_request`. |

## Implementation details

- Our step 43 (`a567cd81d_logs`) implements better error logging in `send_request`.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
