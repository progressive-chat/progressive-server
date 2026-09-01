# Step 572 — "More debug info when try_from_http_request fails" (Conduit `215d909`)

Source: [`timokoesters/conduit@215d909`](https://github.com/timokoesters/conduit/commit/215d909) (2022-10)

## What changed vs step 571

| Rust change | C++ translation |
|---|---|
| More debug info when try_from_http_request fails. Better HTTP request parsing errors. 1 file changed. | **Translated** — Our HTTP parsing (httplib) has errors. This adds debug info in Rust. |

## Implementation details

- Our HTTP parsing (httplib) has errors. This adds debug info in Rust.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
