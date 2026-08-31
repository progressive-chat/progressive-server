# Step 523 — "messing with trait objects" (Conduit `face766`)

Source: [`timokoesters/conduit@face766`](https://github.com/timokoesters/conduit/commit/face766) (2022-10)

## What changed vs step 522

| Rust change | C++ translation |
|---|---|
| Messing with trait objects. Trait object experimentation. 61 files changed. | **No-op for us** — Rust trait objects — our C++ uses different patterns. |

## Implementation details

- Rust trait objects — our C++ uses different patterns.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
