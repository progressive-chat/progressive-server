# Step 365 — "improvement, maybe not safe" (Conduit `ee3d2db`)

Source: [`timokoesters/conduit@ee3d2db`](https://github.com/timokoesters/conduit/commit/ee3d2db) (2022-01)

## What changed vs step 364

| Rust change | C++ translation |
|---|---|
| Improvement, maybe not safe. Risky optimization attempt. 1 file changed. | **Translated** — Risky optimization — our codebase uses safe patterns. |

## Implementation details

- Risky optimization — our codebase uses safe patterns.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
