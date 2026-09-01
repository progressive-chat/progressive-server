# Step 632 — "fix: SRV lookups should end with a period" (Conduit `27f29ba`)

Source: [`timokoesters/conduit@27f29ba`](https://github.com/timokoesters/conduit/commit/27f29ba) (2023-03)

## What changed vs step 631

| Rust change | C++ translation |
|---|---|
| Fix: SRV lookups should end with a period. DNS SRV record format fix. | **Translated** — Related to step 96 (e08dfd9_srv_record). Fixes SRV format. |

## Implementation details

- Related to step 96 (e08dfd9_srv_record). Fixes SRV format.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
