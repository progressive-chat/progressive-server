# Step 229 — "Send proper Host header in federation requests" (Conduit `7b3fe88`)

Source: [`timokoesters/conduit@7b3fe88`](https://github.com/timokoesters/conduit/commit/7b3fe88) (2021-03)

## What changed vs step 228

| Rust change | C++ translation |
|---|---|
| Send proper Host header in federation requests. Some servers require correct Host header. | **Translated** — Our `send_request` (step 29) sets Host header. This ensures it's correct. |

## Implementation details

- Our `send_request` (step 29) sets Host header. This ensures it's correct.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
