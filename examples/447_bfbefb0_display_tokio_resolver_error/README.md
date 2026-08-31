# Step 447 — "Display actual error message from TokioAsyncResolver, if any" (Conduit `bfbefb0`)

Source: [`timokoesters/conduit@bfbefb0`](https://github.com/timokoesters/conduit/commit/bfbefb0) (2022-02)

## What changed vs step 446

| Rust change | C++ translation |
|---|---|
| Display actual error message from TokioAsyncResolver, if any. Better DNS resolution error reporting. | **Translated** — Our DNS resolution (step 29) shows errors. This improves error messages. |

## Implementation details

- Our DNS resolution (step 29) shows errors. This improves error messages.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
