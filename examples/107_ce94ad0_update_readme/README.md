# Step 107 — "Update README.md" (Conduit `ce94ad0`)

Source: [`timokoesters/conduit@ce94ad0`](https://github.com/timokoesters/conduit/commit/ce94ad0) (2020-10)

## What changed vs step 106

| Rust change | C++ translation |
|---|---|
| Update README.md (no code change). | **Skipped** — Documentation only. |

## Implementation details

- Documentation only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
