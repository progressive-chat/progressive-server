# Step 237 — "fix: membership deserializing" (Conduit `84f4ce7`)

Source: [`timokoesters/conduit@84f4ce7`](https://github.com/timokoesters/conduit/commit/84f4ce7) (2021-04)

## What changed vs step 236

| Rust change | C++ translation |
|---|---|
| Fix: membership deserializing. Correctly parse membership events (join/leave/ban/invite) from federation. | **Translated** — Our membership handling (step 16 `76b6f0c_membership_change`) parses correctly. This fixes a Rust deserialization bug. |

## Implementation details

- Our membership handling (step 16 `76b6f0c_membership_change`) parses correctly. This fixes a Rust deserialization bug.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
