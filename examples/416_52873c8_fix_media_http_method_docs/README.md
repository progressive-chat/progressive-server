# Step 416 — "Fix incorrect HTTP method in doc comments of two media routes" (Conduit `52873c8`)

Source: [`timokoesters/conduit@52873c8`](https://github.com/timokoesters/conduit/commit/52873c8) (2022-01)

## What changed vs step 415

| Rust change | C++ translation |
|---|---|
| Fix incorrect HTTP method in doc comments of two media routes. Documentation fix. | **Skipped** — Documentation only. |

## Implementation details

- Documentation only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
