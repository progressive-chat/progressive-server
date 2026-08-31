# Step 153 — "improvement: better warnings when server is unreachable" (Conduit `fb9bd34`)

Source: [`timokoesters/conduit@fb9bd34`](https://github.com/timokoesters/conduit/commit/fb9bd34) (2020-12)

## What changed vs step 152

| Rust change | C++ translation |
|---|---|
| Improvement: better warnings when server is unreachable. Logs the reason for the unreachable server. | **Translated** — Our `send_request` logs federation errors via std::cerr. |

## Implementation details

- Our `send_request` logs federation errors via std::cerr.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
