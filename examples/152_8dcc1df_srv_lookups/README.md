# Step 152 — "improvement: always use port from SRV lookups" (Conduit `8dcc1df`)

Source: [`timokoesters/conduit@8dcc1df`](https://github.com/timokoesters/conduit/commit/8dcc1df) (2020-12)

## What changed vs step 151

| Rust change | C++ translation |
|---|---|
| Improvement: always use port from SRV lookups when sending federation requests. | **Translated** — Our `send_request` doesn't do SRV lookups. See step 96 (`e08dfd9_srv_record`) for the related SRV work. |

## Implementation details

- Our `send_request` doesn't do SRV lookups. See step 96 (`e08dfd9_srv_record`) for the related SRV work.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
