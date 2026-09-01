# Step 610 — "document `trusted_servers` option" (Conduit `844508b`)

Source: [`timokoesters/conduit@844508b`](https://github.com/timokoesters/conduit/commit/844508b) (2023-01)

## What changed vs step 609

| Rust change | C++ translation |
|---|---|
| Document `trusted_servers` option. Config documentation. | **Skipped** — Documentation only. |

## Implementation details

- Documentation only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
