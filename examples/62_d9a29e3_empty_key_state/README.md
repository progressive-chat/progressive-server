# Step 62 — "Fix state for empty key route" (Conduit `d9a29e3`)

Source: [`timokoesters/conduit@d9a29e3`](https://github.com/timokoesters/conduit/commit/d9a29e3) (2020-08)

## What changed vs step 61

| Rust change | C++ translation |
|---|---|
| Fixes a state-res bug for the empty-key route. The `/state/` endpoint (no specific state key) was returning incorrect data. | **Translated** — our `state_res.cpp` handles this case correctly. |

## Implementation details

- **Translated** — our `state_res.cpp` handles this case correctly.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
