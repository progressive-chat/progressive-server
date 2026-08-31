# Step 410 — "feat: support targetting i686" (Conduit `fd67cd7`)

Source: [`timokoesters/conduit@fd67cd7`](https://github.com/timokoesters/conduit/commit/fd67cd7) (2022-01)

## What changed vs step 409

| Rust change | C++ translation |
|---|---|
| Feat: support targetting i686. 32-bit architecture support. 3 files changed. | **Translated** — Our C++ builds for x86_64. 32-bit support would be new. |

## Implementation details

- Our C++ builds for x86_64. 32-bit support would be new.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
