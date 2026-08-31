# Step 323 — "fix errors introduced by rebase" (Conduit `f25f61d`)

Source: [`timokoesters/conduit@f25f61d`](https://github.com/timokoesters/conduit/commit/f25f61d) (2021-07)

## What changed vs step 322

| Rust change | C++ translation |
|---|---|
| Fix errors introduced by rebase. Code fixes after git rebase. | **Translated** — Code fixes — our codebase doesn't have these rebase errors. |

## Implementation details

- Code fixes — our codebase doesn't have these rebase errors.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
