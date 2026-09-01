# Step 751 — "add our own binary cache" (Conduit `6ae7762`)

Source: [`timokoesters/conduit@6ae7762`](https://github.com/timokoesters/conduit/commit/6ae7762) (2024-01)

## What changed vs step 750

| Rust change | C++ translation |
|---|---|
| Add our own binary cache. Custom binary cache setup. | **Skipped** — CI only. |

## Implementation details

- CI only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
