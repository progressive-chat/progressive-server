# Step 117 — "improvement: more reliable federation sending" (Conduit `2f5df4a`)

Source: [`timokoesters/conduit@2f5df4a`](https://github.com/timokoesters/conduit/commit/2f5df4a) (2020-10)

## What changed vs step 116

| Rust change | C++ translation |
|---|---|
| Improves the reliability of federation sending. Adds retry logic and better error handling. | **Translated** — Our federation send (step 35) is fire-and-forget. The 50-PDU limit (step 99) provides backpressure. |

## Implementation details

- Our federation send (step 35) is fire-and-forget. The 50-PDU limit (step 99) provides backpressure.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
