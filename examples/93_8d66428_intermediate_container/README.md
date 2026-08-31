# Step 93 — "Add intermediate container to hide ARGs" (Conduit `8d66428`)

Source: [`timokoesters/conduit@8d66428`](https://github.com/timokoesters/conduit/commit/8d66428) (2020-09)

## What changed vs step 92

| Rust change | C++ translation |
|---|---|
| Docker: adds an intermediate container stage to hide build ARGs. | Pure Docker infrastructure change. |

## Implementation details

- Pure Docker infrastructure change.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
