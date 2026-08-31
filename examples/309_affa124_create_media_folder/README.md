# Step 309 — "create media folder in init" (Conduit `affa124`)

Source: [`timokoesters/conduit@affa124`](https://github.com/timokoesters/conduit/commit/affa124) (2021-06)

## What changed vs step 308

| Rust change | C++ translation |
|---|---|
| Create media folder in init. Ensure media directory exists on startup. | **Translated** — Our media init creates directories. This ensures the folder exists. |

## Implementation details

- Our media init creates directories. This ensures the folder exists.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
