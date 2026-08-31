# Step 373 — "fix: incremental lazy loading" (Conduit `c6d8835`)

Source: [`timokoesters/conduit@c6d8835`](https://github.com/timokoesters/conduit/commit/c6d8835) (2022-01)

## What changed vs step 372

| Rust change | C++ translation |
|---|---|
| Fix: incremental lazy loading. Fix interaction between lazy loading and incremental sync. 1 file changed. | **Translated** — Related to steps 369-370. Fixes the lazy loading + incremental sync combo. |

## Implementation details

- Related to steps 369-370. Fixes the lazy loading + incremental sync combo.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
