# Step 709 — "update base64 to 0.21.2" (Conduit `5a7bade`)

Source: [`timokoesters/conduit@5a7bade`](https://github.com/timokoesters/conduit/commit/5a7bade) (2023-08)

## What changed vs step 708

| Rust change | C++ translation |
|---|---|
| Update base64 to 0.21.2. Dependency version bump. 5 files changed. | **Skipped** — Rust dependency upgrade — no direct C++ equivalent. |

## Implementation details

- Rust dependency upgrade — no direct C++ equivalent.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
