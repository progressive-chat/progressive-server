# Step 486 — "Notify admin room for user registrations, deactivations and password changes" (Conduit `b5b8181`)

Source: [`timokoesters/conduit@b5b8181`](https://github.com/timokoesters/conduit/commit/b5b8181) (2022-03)

## What changed vs step 485

| Rust change | C++ translation |
|---|---|
| Notify admin room for user registrations, deactivations and password changes. Admin room notifications. 1 file changed. | **Translated** — Our admin room (step 60) gets notifications. This adds user event notifications. |

## Implementation details

- Our admin room (step 60) gets notifications. This adds user event notifications.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
