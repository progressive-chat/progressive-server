# Step 397 — "feat: implement server ACLs" (Conduit `ee8e72f`)

Source: [`timokoesters/conduit@ee8e72f`](https://github.com/timokoesters/conduit/commit/ee8e72f) (2022-01)

## What changed vs step 396

| Rust change | C++ translation |
|---|---|
| Feat: implement server ACLs. Access Control Lists for server-level permissions. 10 files changed. MAJOR security feature. | **Translated** — We don't have server ACLs yet. This adds server-level access control. |

## Implementation details

- We don't have server ACLs yet. This adds server-level access control.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
