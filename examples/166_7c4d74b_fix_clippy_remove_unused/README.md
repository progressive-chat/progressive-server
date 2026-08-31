# Step 166 — "Fix clippy warnings remove unused imports" (Conduit `7c4d74b`)

Source: [`timokoesters/conduit@7c4d74b`](https://github.com/timokoesters/conduit/commit/7c4d74b) (2021-01)

## What changed vs step 165

| Rust change | C++ translation |
|---|---|
| Fix clippy warnings, remove unused imports. | **No-op for us** — Rust linter changes — N/A for C++. |

## Implementation details

- Rust linter changes — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
