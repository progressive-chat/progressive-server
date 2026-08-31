# Step 161 — "improvement: send 200 response for turn server info" (Conduit `ad7b3f1`)

Source: [`timokoesters/conduit@ad7b3f1`](https://github.com/timokoesters/conduit/commit/ad7b3f1) (2021-01)

## What changed vs step 160

| Rust change | C++ translation |
|---|---|
| Improvement: send 200 response for turn server info. Returns proper JSON instead of empty body. | **Translated** — Our `/voip/turnServer` (step 8) returns proper JSON. |

## Implementation details

- Our `/voip/turnServer` (step 8) returns proper JSON.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
