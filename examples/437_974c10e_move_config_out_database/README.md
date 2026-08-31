# Step 437 — "Move Config out of database module" (Conduit `974c10e`)

Source: [`timokoesters/conduit@974c10e`](https://github.com/timokoesters/conduit/commit/974c10e) (2022-02)

## What changed vs step 436

| Rust change | C++ translation |
|---|---|
| Move Config out of database module. Code organization: config struct moved to separate module. 4 files changed. | **Translated** — Our config is already separate (step 99 in tail). This is a Rust module reorganization. |

## Implementation details

- Our config is already separate (step 99 in tail). This is a Rust module reorganization.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
