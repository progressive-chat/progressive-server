# Step 456 — "fix compilations" (Conduit `35b82d5`)

Source: [`timokoesters/conduit@35b82d5`](https://github.com/timokoesters/conduit/commit/35b82d5) (2022-02)

## What changed vs step 455

| Rust change | C++ translation |
|---|---|
| Fix compilations. Compilation error fixes after Rocket->axum migration. 3 files changed. | **Translated** — Post-migration compilation fixes — our C++ compiles clean. |

## Implementation details

- Post-migration compilation fixes — our C++ compiles clean.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
