# Step 246 — "feat: reject invites over federation" (Conduit `b4f79b7`)

Source: [`timokoesters/conduit@b4f79b7`](https://github.com/timokoesters/conduit/commit/b4f79b7) (2021-04)

## What changed vs step 245

| Rust change | C++ translation |
|---|---|
| Feat: reject invites over federation. Allow users to reject incoming federation invites. 10 files changed. MAJOR feature. | **Translated** — Our federation invite (step 93) handles invites. Reject is a new action on invites. |

## Implementation details

- Our federation invite (step 93) handles invites. Reject is a new action on invites.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
