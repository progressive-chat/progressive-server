# Step 422 — "fix: mention dependencies to build from source" (Conduit `8ff95a5`)

Source: [`timokoesters/conduit@8ff95a5`](https://github.com/timokoesters/conduit/commit/8ff95a5) (2022-01)

## What changed vs step 421

| Rust change | C++ translation |
|---|---|
| Fix: mention dependencies to build from source. Documentation/build instructions. | **Skipped** — Documentation only. |

## Implementation details

- Documentation only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
