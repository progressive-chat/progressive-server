# Step 644 — "factor out shared things" (Conduit `3be32c4`)

Source: [`timokoesters/conduit@3be32c4`](https://github.com/timokoesters/conduit/commit/3be32c4) (2023-04)

## What changed vs step 643

| Rust change | C++ translation |
|---|---|
| Factor out shared things. Code deduplication. 1 file changed. | **Translated** — Code deduplication — our codebase is already DRY. |

## Implementation details

- Code deduplication — our codebase is already DRY.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
