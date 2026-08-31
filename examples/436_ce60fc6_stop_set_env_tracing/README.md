# Step 436 — "Stop using set_env to configure tracing-subscriber" (Conduit `ce60fc6`)

Source: [`timokoesters/conduit@ce60fc6`](https://github.com/timokoesters/conduit/commit/ce60fc6) (2022-02)

## What changed vs step 435

| Rust change | C++ translation |
|---|---|
| Stop using set_env to configure tracing-subscriber. Rust logging configuration change. | **No-op for us** — Rust tracing-subscriber config — our C++ uses std::cerr. |

## Implementation details

- Rust tracing-subscriber config — our C++ uses std::cerr.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
