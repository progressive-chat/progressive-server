# Step 503 — "Fix spelling." (Conduit `bd3f9e0`)

Source: [`timokoesters/conduit@bd3f9e0`](https://github.com/timokoesters/conduit/commit/bd3f9e0) (2022-06)

## What changed vs step 502

| Rust change | C++ translation |
|---|---|
| Fix spelling. Typo fixes. | **No-op for us** — Spelling — our codebase has its own. |

## Implementation details

- Spelling — our codebase has its own.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
