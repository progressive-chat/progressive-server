# Step 516 — "Bump version to 0.4" (Conduit `35fd732`)

Source: [`timokoesters/conduit@35fd732`](https://github.com/timokoesters/conduit/commit/35fd732) (2022-06)

## What changed vs step 515

| Rust change | C++ translation |
|---|---|
| Bump version to 0.4. Version number update. | **Skipped** — Version bump only. |

## Implementation details

- Version bump only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
