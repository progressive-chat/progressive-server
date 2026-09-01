# Step 597 — "Replace println/dbg calls with corresponding macros from tracing crate" (Conduit `2a0515f`)

Source: [`timokoesters/conduit@2a0515f`](https://github.com/timokoesters/conduit/commit/2a0515f) (2022-12)

## What changed vs step 596

| Rust change | C++ translation |
|---|---|
| Replace println/dbg calls with corresponding macros from tracing crate. Logging modernization. 5 files changed. | **No-op for us** — Rust tracing crate — our C++ uses std::cerr. |

## Implementation details

- Rust tracing crate — our C++ uses std::cerr.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
