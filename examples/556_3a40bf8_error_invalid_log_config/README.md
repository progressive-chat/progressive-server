# Step 556 — "Add error for invalid log config" (Conduit `3a40bf8`)

Source: [`timokoesters/conduit@3a40bf8`](https://github.com/timokoesters/conduit/commit/3a40bf8) (2022-10)

## What changed vs step 555

| Rust change | C++ translation |
|---|---|
| Add error for invalid log config. Validate logging configuration on startup. | **Translated** — Our config validation could add log config validation. |

## Implementation details

- Our config validation could add log config validation.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
