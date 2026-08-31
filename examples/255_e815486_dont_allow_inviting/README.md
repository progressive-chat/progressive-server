# Step 255 — "fix: don't allow inviting other users (not implemented yet)" (Conduit `e815486`)

Source: [`timokoesters/conduit@e815486`](https://github.com/timokoesters/conduit/commit/e815486) (2021-04)

## What changed vs step 254

| Rust change | C++ translation |
|---|---|
| Fix: don't allow inviting other users (not implemented yet). Returns error for invite attempts until feature is ready. | **Translated** — Our invite handling (step 241, 246) already implements invites. This was a Rust stub. |

## Implementation details

- Our invite handling (step 241, 246) already implements invites. This was a Rust stub.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
