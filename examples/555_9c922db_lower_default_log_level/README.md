# Step 555 — "Lower default log level" (Conduit `9c922db`)

Source: [`timokoesters/conduit@9c922db`](https://github.com/timokoesters/conduit/commit/9c922db) (2022-10)

## What changed vs step 554

| Rust change | C++ translation |
|---|---|
| Lower default log level. Reduce verbosity of default logging. 2 files changed. | **Translated** — Our logging (std::cerr) uses INFO by default. This lowers it to WARN. |

## Implementation details

- Our logging (std::cerr) uses INFO by default. This lowers it to WARN.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
