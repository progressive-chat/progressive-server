# Step 575 — "fix(main): fix request size limit to max_request_size (axum defaults 2MB)" (Conduit `10d2da3`)

Source: [`timokoesters/conduit@10d2da3`](https://github.com/timokoesters/conduit/commit/10d2da3) (2022-10)

## What changed vs step 574

| Rust change | C++ translation |
|---|---|
| Fix(main): fix request size limit to max_request_size (axum defaults 2MB). Configure max request body size. 3 files changed. | **Translated** — Our httplib (step 6) has a request size limit. This configures it properly. |

## Implementation details

- Our httplib (step 6) has a request size limit. This configures it properly.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
