# Step 116 — "improvement: welcome message" (Conduit `df82314`)

Source: [`timokoesters/conduit@df82314`](https://github.com/timokoesters/conduit/commit/df82314) (2020-10)

## What changed vs step 115

| Rust change | C++ translation |
|---|---|
| Adds a welcome message on startup that prints the server URL and config summary. | **No-op for us** — Our server prints basic startup info but no formal welcome message. |

## Implementation details

- Our server prints basic startup info but no formal welcome message.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
