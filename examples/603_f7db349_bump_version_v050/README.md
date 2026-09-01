# Step 603 — "Bump version to v0.5.0" (Conduit `f7db349`)

Source: [`timokoesters/conduit@f7db349`](https://github.com/timokoesters/conduit/commit/f7db349) (2022-12)

## What changed vs step 602

| Rust change | C++ translation |
|---|---|
| Bump version to v0.5.0. Version release. | **Skipped** — Version bump only. |

## Implementation details

- Version bump only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
