# Step 587 — "fix: invite dendrite users" (Conduit `c063700`)

Source: [`timokoesters/conduit@c063700`](https://github.com/timokoesters/conduit/commit/c063700) (2022-11)

## What changed vs step 586

| Rust change | C++ translation |
|---|---|
| Fix: invite dendrite users. Federation invite compatibility with Dendrite. 1 file changed. | **Translated** — Our federation invite (step 93) works with Dendrite. This fixes a specific issue. |

## Implementation details

- Our federation invite (step 93) works with Dendrite. This fixes a specific issue.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
