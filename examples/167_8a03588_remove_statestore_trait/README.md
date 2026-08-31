# Step 167 — "Remove StateStore trait from state-res collect events needed" (Conduit `8a03588`)

Source: [`timokoesters/conduit@8a03588`](https://github.com/timokoesters/conduit/commit/8a03588) (2021-01)

## What changed vs step 166

| Rust change | C++ translation |
|---|---|
| Remove `StateStore` trait from state-res, collect events needed for resolution directly. | **No-op for us** — Rust trait refactor — our C++ state-res doesn't use traits. |

## Implementation details

- Rust trait refactor — our C++ state-res doesn't use traits.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
