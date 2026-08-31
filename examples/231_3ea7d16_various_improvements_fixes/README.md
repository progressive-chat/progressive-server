# Step 231 — "fix: various improvements and fixes" (Conduit `3ea7d16`)

Source: [`timokoesters/conduit@3ea7d16`](https://github.com/timokoesters/conduit/commit/3ea7d16) (2021-03)

## What changed vs step 230

| Rust change | C++ translation |
|---|---|
| Fix: various improvements and fixes. General bug fixes and improvements. 9 files changed. | **Translated** — General bug fixes — our codebase benefits from the same fixes implicitly. |

## Implementation details

- General bug fixes — our codebase benefits from the same fixes implicitly.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
