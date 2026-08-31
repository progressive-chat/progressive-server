# Step 239 — "fix: lost forward extremity" (Conduit `588de12`)

Source: [`timokoesters/conduit@588de12`](https://github.com/timokoesters/conduit/commit/588de12) (2021-04)

## What changed vs step 238

| Rust change | C++ translation |
|---|---|
| Fix: lost forward extremity. Forward extremity could be lost in some edge cases during state resolution. | **Translated** — Our `pdu_leaves_replace` (step 66) maintains forward extremities correctly. |

## Implementation details

- Our `pdu_leaves_replace` (step 66) maintains forward extremities correctly.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
