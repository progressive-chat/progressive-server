# Step 319 — "Export conduits Config struct and fix clipp warningsy" (Conduit `09a8737`)

Source: [`timokoesters/conduit@09a8737`](https://github.com/timokoesters/conduit/commit/09a8737) (2021-06)

## What changed vs step 318

| Rust change | C++ translation |
|---|---|
| Export conduit's Config struct and fix clippy warnings. Make config struct public for external use. 4 files changed. | **No-op for us** — Rust struct export — our config is internal C++ struct. |

## Implementation details

- Rust struct export — our config is internal C++ struct.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
