# Step 296 — "Fix docker-compose trusted_servers env var" (Conduit `8387cea`)

Source: [`timokoesters/conduit@8387cea`](https://github.com/timokoesters/conduit/commit/8387cea) (2021-05)

## What changed vs step 295

| Rust change | C++ translation |
|---|---|
| Fix docker-compose trusted_servers env var. Docker configuration fix. | **Translated** — Matches step 291 — Docker env var for trusted_servers. |

## Implementation details

- Matches step 291 — Docker env var for trusted_servers.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
