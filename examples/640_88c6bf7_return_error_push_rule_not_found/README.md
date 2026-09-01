# Step 640 — "Always return an error if a push rule is not found" (Conduit `88c6bf7`)

Source: [`timokoesters/conduit@88c6bf7`](https://github.com/timokoesters/conduit/commit/88c6bf7) (2023-03)

## What changed vs step 639

| Rust change | C++ translation |
|---|---|
| Always return an error if a push rule is not found. Push rule lookup error handling. | **Translated** — Our push rules return errors. This ensures proper error in Rust. |

## Implementation details

- Our push rules return errors. This ensures proper error in Rust.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
