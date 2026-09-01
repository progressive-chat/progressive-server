# Step 634 — "Reduce logs from info to debug" (Conduit `63f787f`)

Source: [`timokoesters/conduit@63f787f`](https://github.com/timokoesters/conduit/commit/63f787f) (2023-03)

## What changed vs step 633

| Rust change | C++ translation |
|---|---|
| Reduce logs from info to debug. Log level reduction for verbose operations. 3 files changed. | **Translated** — Matches steps 555-558 — log level reduction. |

## Implementation details

- Matches steps 555-558 — log level reduction.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
