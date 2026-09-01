# Step 600 — "feat: Implement membership ban/join/leave/invite reason support" (Conduit `7cc346b`)

Source: [`timokoesters/conduit@7cc346b`](https://github.com/timokoesters/conduit/commit/7cc346b) (2022-12)

## What changed vs step 599

| Rust change | C++ translation |
|---|---|
| Feat: Implement membership ban/join/leave/invite reason support. Reason field for membership events. 2 files changed. | **Translated** — Our membership (step 16) doesn't have reasons. This adds the reason field. |

## Implementation details

- Our membership (step 16) doesn't have reasons. This adds the reason field.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
