# Step 725 — "fix: ACL error shouldn't break the whole request" (Conduit `f73a657`)

Source: [`timokoesters/conduit@f73a657`](https://github.com/timokoesters/conduit/commit/f73a657) (2023-08)

## What changed vs step 724

| Rust change | C++ translation |
|---|---|
| Fix: ACL error shouldn't break the whole request. ACL (server ACLs, step 397) error handling. 2 files changed. | **Translated** — Our ACLs (step 397) handle errors. This ensures ACL errors don't break requests. |

## Implementation details

- Our ACLs (step 397) handle errors. This ensures ACL errors don't break requests.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
