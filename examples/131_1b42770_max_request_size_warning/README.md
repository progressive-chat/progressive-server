# Step 131 — "improvement: warning for small max_request_size values" (Conduit `1b42770`)

Source: [`timokoesters/conduit@1b42770`](https://github.com/timokoesters/conduit/commit/1b42770) (2021-05-22)

## What changed vs step 130

| Rust change | C++ translation |
|---|---|
| **Warning for small max_request_size** | **Translated** — max_request_size warning |

## Implementation details

1. **max_request_size warning** — Warning for small max_request_size values

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
