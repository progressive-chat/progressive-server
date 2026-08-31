# Step 513 — "Implement command to deactivate user from admin channel" (Conduit `f6183e4`)

Source: [`timokoesters/conduit@f6183e4`](https://github.com/timokoesters/conduit/commit/f6183e4) (2022-06)

## What changed vs step 512

| Rust change | C++ translation |
|---|---|
| Implement command to deactivate user from admin channel. Admin user deactivation. 3 files changed. | **Translated** — Related to step 304 (deactivate accounts). This adds admin command for it. |

## Implementation details

- Related to step 304 (deactivate accounts). This adds admin command for it.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
