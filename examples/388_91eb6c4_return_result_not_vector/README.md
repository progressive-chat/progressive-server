# Step 388 — "Return a Result instead of a vector" (Conduit `91eb6c4`)

Source: [`timokoesters/conduit@91eb6c4`](https://github.com/timokoesters/conduit/commit/91eb6c4) (2022-01)

## What changed vs step 387

| Rust change | C++ translation |
|---|---|
| Return a Result instead of a vector. Error handling improvement in database layer. | **Translated** — Our DB methods return Result. This changes Rust Vec to Result for errors. |

## Implementation details

- Our DB methods return Result. This changes Rust Vec to Result for errors.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
