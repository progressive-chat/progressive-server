# Step 561 — "fix(service/rooms/timeline): fix validating for non-joined members" (Conduit `e923f63`)

Source: [`timokoesters/conduit@e923f63`](https://github.com/timokoesters/conduit/commit/e923f63) (2022-10)

## What changed vs step 560

| Rust change | C++ translation |
|---|---|
| Fix(service/rooms/timeline): fix validating for non-joined members. Timeline validation for non-members. 1 file changed. | **Translated** — Our timeline (step 6) validates membership. This fixes the Rust version. |

## Implementation details

- Our timeline (step 6) validates membership. This fixes the Rust version.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
