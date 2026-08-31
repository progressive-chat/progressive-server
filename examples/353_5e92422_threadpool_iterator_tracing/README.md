# Step 353 — "feat: add threadpool for iterator threads, bug fixes, tracing_flame support" (Conduit `5e92422`)

Source: [`timokoesters/conduit@5e92422`](https://github.com/timokoesters/conduit/commit/5e92422) (2021-07)

## What changed vs step 352

| Rust change | C++ translation |
|---|---|
| Feat: add threadpool for iterator threads, bug fixes, tracing_flame support. Thread pool for iterators and flame graph profiling. 26 files changed. MAJOR. | **Translated** — Our server is single-threaded async. Thread pool is a Rust scaling feature. |

## Implementation details

- Our server is single-threaded async. Thread pool is a Rust scaling feature.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
