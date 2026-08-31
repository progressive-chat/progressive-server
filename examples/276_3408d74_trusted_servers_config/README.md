# Step 276 — "fix: add trusted_servers to config and deploy guide" (Conduit `3408d74`)

Source: [`timokoesters/conduit@3408d74`](https://github.com/timokoesters/conduit/commit/3408d74) (2021-05)

## What changed vs step 275

| Rust change | C++ translation |
|---|---|
| Fix: add trusted_servers to config and deploy guide. Config option for trusted key servers. | **Translated** — Our step 215 (79c9de9) added trusted_servers logic. This adds the config option. |

## Implementation details

- Our step 215 (79c9de9) added trusted_servers logic. This adds the config option.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
