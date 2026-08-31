# Step 262 — "fix: only show one typing event per user" (Conduit `bb234ca`)

Source: [`timokoesters/conduit@bb234ca`](https://github.com/timokoesters/conduit/commit/bb234ca) (2021-04)

## What changed vs step 261

| Rust change | C++ translation |
|---|---|
| Fix: only show one typing event per user. Deduplicate typing notifications. | **Translated** — Our typing (step 15 `6c76874_typing`) shows one per user. This fixes a bug. |

## Implementation details

- Our typing (step 15 `6c76874_typing`) shows one per user. This fixes a bug.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
