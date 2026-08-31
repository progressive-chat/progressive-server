# Step 157 — "improvement: change federation_enabled to federation_disabled" (Conduit `85364a9`)

Source: [`timokoesters/conduit@85364a9`](https://github.com/timokoesters/conduit/commit/85364a9) (2021-01)

## What changed vs step 156

| Rust change | C++ translation |
|---|---|
| Improvement: change `federation_enabled` config to `federation_disabled` (inverted default). Federation is now opt-out, not opt-in. | **No-op for us** — Our federation is always on. A config layer would be needed for opt-out. |

## Implementation details

- Our federation is always on. A config layer would be needed for opt-out.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
