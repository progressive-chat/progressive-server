# Step 617 — "fix: allow reactivation of users using reset-password admin command" (Conduit `fc0aff2`)

Source: [`timokoesters/conduit@fc0aff2`](https://github.com/timokoesters/conduit/commit/fc0aff2) (2023-02)

## What changed vs step 616

| Rust change | C++ translation |
|---|---|
| Fix: allow reactivation of users using reset-password admin command. Account reactivation via admin. 1 file changed. | **Translated** — Related to step 513 (admin deactivate user). This adds reactivation. |

## Implementation details

- Related to step 513 (admin deactivate user). This adds reactivation.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
