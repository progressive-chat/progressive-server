# Step 619 — "feat: ask for backfill" (Conduit `7bdd966`)

Source: [`timokoesters/conduit@7bdd966`](https://github.com/timokoesters/conduit/commit/7bdd966) (2023-03)

## What changed vs step 618

| Rust change | C++ translation |
|---|---|
| Feat: ask for backfill. Request backfill from remote servers. 12 files changed. MAJOR feature. | **Translated** — We don't have backfill. This adds the outbound backfill request logic. |

## Implementation details

- We don't have backfill. This adds the outbound backfill request logic.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
