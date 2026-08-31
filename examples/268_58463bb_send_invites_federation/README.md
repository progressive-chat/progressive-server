# Step 268 — "feat: send invites over federation" (Conduit `58463bb`)

Source: [`timokoesters/conduit@58463bb`](https://github.com/timokoesters/conduit/commit/58463bb) (2021-04)

## What changed vs step 267

| Rust change | C++ translation |
|---|---|
| Feat: send invites over federation. Outgoing invites to remote servers. 5 files changed. MAJOR feature. | **Translated** — Our federation invite (step 93) handles incoming. This adds outgoing invites. |

## Implementation details

- Our federation invite (step 93) handles incoming. This adds outgoing invites.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
