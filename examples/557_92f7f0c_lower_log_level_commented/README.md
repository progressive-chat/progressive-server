# Step 557 — "Lower log level commented config options" (Conduit `92f7f0c`)

Source: [`timokoesters/conduit@92f7f0c`](https://github.com/timokoesters/conduit/commit/92f7f0c) (2022-10)

## What changed vs step 556

| Rust change | C++ translation |
|---|---|
| Lower log level commented config options. Commented-out config examples with lower log level. | **No-op for us** — Config example comments only. |

## Implementation details

- Config example comments only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
