# Step 604 — "Bump version to 0.6.0-alpha" (Conduit `2a66ad4`)

Source: [`timokoesters/conduit@2a66ad4`](https://github.com/timokoesters/conduit/commit/2a66ad4) (2022-12)

## What changed vs step 603

| Rust change | C++ translation |
|---|---|
| Bump version to 0.6.0-alpha. Version release. | **Skipped** — Version bump only. |

## Implementation details

- Version bump only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
