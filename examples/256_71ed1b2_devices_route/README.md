# Step 256 — "feat: /devices route" (Conduit `71ed1b2`)

Source: [`timokoesters/conduit@71ed1b2`](https://github.com/timokoesters/conduit/commit/71ed1b2) (2021-04)

## What changed vs step 255

| Rust change | C++ translation |
|---|---|
| Feat: `/devices` route. List and manage user devices (for logout, device verification). 4 files changed. | **Translated** — We have device listing in account management. This adds the full `/devices` API. |

## Implementation details

- We have device listing in account management. This adds the full `/devices` API.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
