# Step 241 — "feat: incoming invites over federation" (Conduit `8773e50`)

Source: [`timokoesters/conduit@8773e50`](https://github.com/timokoesters/conduit/commit/8773e50) (2021-04)

## What changed vs step 240

| Rust change | C++ translation |
|---|---|
| Feat: incoming invites over federation. Handle invite events from remote servers. 10 files changed. MAJOR feature. | **Translated** — Our federation invite (step 93 `3db42bd_federation_invite_refactor`) handles incoming invites. This is the Rust implementation. |

## Implementation details

- Our federation invite (step 93 `3db42bd_federation_invite_refactor`) handles incoming invites. This is the Rust implementation.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
