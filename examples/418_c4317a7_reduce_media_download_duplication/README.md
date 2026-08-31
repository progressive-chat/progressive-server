# Step 418 — "Reduce code duplication in media download route handlers" (Conduit `c4317a7`)

Source: [`timokoesters/conduit@c4317a7`](https://github.com/timokoesters/conduit/commit/c4317a7) (2022-01)

## What changed vs step 417

| Rust change | C++ translation |
|---|---|
| Reduce code duplication in media download route handlers. DRY refactor. 1 file changed. | **Translated** — Our media handlers (step 14) are already DRY. This refactors the Rust version. |

## Implementation details

- Our media handlers (step 14) are already DRY. This refactors the Rust version.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
