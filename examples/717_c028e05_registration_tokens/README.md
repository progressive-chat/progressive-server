# Step 717 — "feat: registration tokens" (Conduit `c028e05`)

Source: [`timokoesters/conduit@c028e05`](https://github.com/timokoesters/conduit/commit/c028e05) (2023-08)

## What changed vs step 716

| Rust change | C++ translation |
|---|---|
| Feat: registration tokens. Token-based registration (invite-only registration). 6 files changed. MAJOR feature. | **Translated** — We don't have registration tokens yet. This adds token-based registration. |

## Implementation details

- We don't have registration tokens yet. This adds token-based registration.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
