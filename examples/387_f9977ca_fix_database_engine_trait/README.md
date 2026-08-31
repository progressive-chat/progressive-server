# Step 387 — "fix: changes to update to the last database engine trait definition" (Conduit `f9977ca`)

Source: [`timokoesters/conduit@f9977ca`](https://github.com/timokoesters/conduit/commit/f9977ca) (2022-01)

## What changed vs step 386

| Rust change | C++ translation |
|---|---|
| Fix: changes to update to the last database engine trait definition. Trait updates for new backend. 2 files changed. | **Translated** — Trait updates for the DatabaseEngine trait (step 375). |

## Implementation details

- Trait updates for the DatabaseEngine trait (step 375).
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
