# Step 386 — "feat: Integration with persy using background ops" (Conduit `ab15ec6`)

Source: [`timokoesters/conduit@ab15ec6`](https://github.com/timokoesters/conduit/commit/ab15ec6) (2022-01)

## What changed vs step 385

| Rust change | C++ translation |
|---|---|
| Feat: Integration with persy using background ops. New database backend (persy) with background operations. 5 files changed. MAJOR. | **Translated** — Related to step 307/374 (swappable DB). Persy is a new backend option. |

## Implementation details

- Related to step 307/374 (swappable DB). Persy is a new backend option.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
