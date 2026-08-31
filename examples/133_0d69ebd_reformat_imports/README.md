# Step 133 — "Reformat imports and fix clippy warnings" (Conduit `0d69ebd`)

Source: [`timokoesters/conduit@0d69ebd`](https://github.com/timokoesters/conduit/commit/0d69ebd) (2020-12)

## What changed vs step 132

| Rust change | C++ translation |
|---|---|
| Reformat imports and fix clippy warnings. | **No-op for us** — Rust formatter/linter changes — N/A for C++. |

## Implementation details

- Rust formatter/linter changes — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
