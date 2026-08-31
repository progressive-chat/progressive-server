# Step 288 — "improvement: warning for small max_request_size values" (Conduit `1b42770`)

Source: [`timokoesters/conduit@1b42770`](https://github.com/timokoesters/conduit/commit/1b42770) (2021-05)

## What changed vs step 287

| Rust change | C++ translation |
|---|---|
| Improvement: warning for small max_request_size values. Config validation warning. | **Translated** — Our config validation could add this warning. |

## Implementation details

- Our config validation could add this warning.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
