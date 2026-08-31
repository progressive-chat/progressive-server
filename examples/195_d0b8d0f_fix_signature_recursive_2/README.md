# Step 195 — "Fix signature/hash checks, fetch recursive auth events" (Conduit `d0b8d0f`)

Source: [`timokoesters/conduit@d0b8d0f`](https://github.com/timokoesters/conduit/commit/d0b8d0f) (2021-02)

## What changed vs step 194

| Rust change | C++ translation |
|---|---|
| Fix signature/hash checks, fetch recursive auth events. Duplicate of step 169 (27c4e9d). | **Translated** — Same as step 169 — our state-res (step 83) handles signatures and auth chain. |

## Implementation details

- Same as step 169 — our state-res (step 83) handles signatures and auth chain.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
