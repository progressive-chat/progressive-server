# Step 433 — "Use prebuilt CI-containers from https://gitlab.com/jfowl/conduit-containers" (Conduit `9478c75`)

Source: [`timokoesters/conduit@9478c75`](https://github.com/timokoesters/conduit/commit/9478c75) (2022-02)

## What changed vs step 432

| Rust change | C++ translation |
|---|---|
| Use prebuilt CI-containers from https://gitlab.com/jfowl/conduit-containers. Duplicate of step 428. 6 files changed. | **No-op for us** — Duplicate of step 428 — Rust CI containers. |

## Implementation details

- Duplicate of step 428 — Rust CI containers.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
