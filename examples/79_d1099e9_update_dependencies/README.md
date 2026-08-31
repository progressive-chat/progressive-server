# Step 79 — "Update dependencies" (Conduit `d1099e9`)

Source: [`timokoesters/conduit@d1099e9`](https://github.com/timokoesters/conduit/commit/d1099e9) (2020-09)

## What changed vs step 78

| Rust change | C++ translation |
|---|---|
| Updates 4 dependencies in `Cargo.lock` (state-res, ring, rsa, sha-1). | Pure `Cargo.lock` dependency bumps. No code change. |

## Implementation details

- Pure `Cargo.lock` dependency bumps. No code change.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
