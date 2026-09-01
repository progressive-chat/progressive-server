# Step 721 — "improvement: matrix.org is default trusted server if unspecified" (Conduit `19bfee1`)

Source: [`timokoesters/conduit@19bfee1`](https://github.com/timokoesters/conduit/commit/19bfee1) (2023-08)

## What changed vs step 720

| Rust change | C++ translation |
|---|---|
| Improvement: matrix.org is default trusted server if unspecified. Default trusted key server. 1 file changed. | **Translated** — Matches step 215 (trusted_servers_config). This sets matrix.org as default. |

## Implementation details

- Matches step 215 (trusted_servers_config). This sets matrix.org as default.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
