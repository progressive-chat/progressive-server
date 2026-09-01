# Step 722 — "Bump version to v0.6.0" (Conduit `5d16948`)

Source: [`timokoesters/conduit@5d16948`](https://github.com/timokoesters/conduit/commit/5d16948) (2023-08)

## What changed vs step 721

| Rust change | C++ translation |
|---|---|
| Bump version to v0.6.0. Version release. | **Skipped** — Version bump only. |

## Implementation details

- Version bump only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
