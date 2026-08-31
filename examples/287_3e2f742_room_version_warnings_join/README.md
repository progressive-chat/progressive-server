# Step 287 — "fix: room version warnings and other bugs when joining rooms" (Conduit `3e2f742`)

Source: [`timokoesters/conduit@3e2f742`](https://github.com/timokoesters/conduit/commit/3e2f742) (2021-05)

## What changed vs step 286

| Rust change | C++ translation |
|---|---|
| Fix: room version warnings and other bugs when joining rooms. Better room version handling on join. | **Translated** — Our room version handling (steps 80-87) supports multiple versions. This fixes join warnings. |

## Implementation details

- Our room version handling (steps 80-87) supports multiple versions. This fixes join warnings.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
