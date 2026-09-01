# Step 577 — "Update nginx configuration to allow for larger uploads." (Conduit `238ebcf`)

Source: [`timokoesters/conduit@238ebcf`](https://github.com/timokoesters/conduit/commit/238ebcf) (2022-10)

## What changed vs step 576

| Rust change | C++ translation |
|---|---|
| Update nginx configuration to allow for larger uploads. Reverse proxy config. | **Skipped** — Nginx config only. |

## Implementation details

- Nginx config only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
