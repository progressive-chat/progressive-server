# Step 699 — "Log the unknown login type in warning level" (Conduit `8631034`)

Source: [`timokoesters/conduit@8631034`](https://github.com/timokoesters/conduit/commit/8631034) (2023-07)

## What changed vs step 698

| Rust change | C++ translation |
|---|---|
| Log the unknown login type in warning level. Better logging for unknown auth types. | **Translated** — Our login (step 13) logs unknown types. This adds warning level logging. |

## Implementation details

- Our login (step 13) logs unknown types. This adds warning level logging.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
