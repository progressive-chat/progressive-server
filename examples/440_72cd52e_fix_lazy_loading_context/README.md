# Step 440 — "fix: lazy loading for /context" (Conduit `72cd52e`)

Source: [`timokoesters/conduit@72cd52e`](https://github.com/timokoesters/conduit/commit/72cd52e) (2022-02)

## What changed vs step 439

| Rust change | C++ translation |
|---|---|
| Fix: lazy loading for /context. Fix lazy loading in the /context endpoint. 1 file changed. | **Translated** — Related to step 369 (lazy loading). This fixes it for /context. |

## Implementation details

- Related to step 369 (lazy loading). This fixes it for /context.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
