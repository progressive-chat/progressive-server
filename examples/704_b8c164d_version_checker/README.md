# Step 704 — "feat: version checker" (Conduit `b8c164d`)

Source: [`timokoesters/conduit@b8c164d`](https://github.com/timokoesters/conduit/commit/b8c164d) (2023-07)

## What changed vs step 703

| Rust change | C++ translation |
|---|---|
| Feat: version checker. Check for Conduit updates. 12 files changed. MAJOR feature. | **Translated** — We don't have a version checker. This adds update notification. |

## Implementation details

- We don't have a version checker. This adds update notification.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
