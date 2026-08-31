# Step 291 — "Add CONDUIT_TRUSTED_SERVERS config param" (Conduit `c6625d8`)

Source: [`timokoesters/conduit@c6625d8`](https://github.com/timokoesters/conduit/commit/c6625d8) (2021-05)

## What changed vs step 290

| Rust change | C++ translation |
|---|---|
| Add CONDUIT_TRUSTED_SERVERS config param. Environment variable for trusted servers. | **Translated** — Matches step 276 — config parameter for trusted_servers. |

## Implementation details

- Matches step 276 — config parameter for trusted_servers.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
