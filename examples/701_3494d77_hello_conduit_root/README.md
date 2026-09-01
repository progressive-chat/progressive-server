# Step 701 — "Return "Hello from Conduit!" on the / route" (Conduit `3494d77`)

Source: [`timokoesters/conduit@3494d77`](https://github.com/timokoesters/conduit/commit/3494d77) (2023-07)

## What changed vs step 700

| Rust change | C++ translation |
|---|---|
| Return "Hello from Conduit!" on the / route. Root endpoint response. | **Translated** — Our root route could return this. Simple welcome message. |

## Implementation details

- Our root route could return this. Simple welcome message.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
