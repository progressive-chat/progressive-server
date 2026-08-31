# Step 324 — "address pr comments" (Conduit `c53cc03`)

Source: [`timokoesters/conduit@c53cc03`](https://github.com/timokoesters/conduit/commit/c53cc03) (2021-07)

## What changed vs step 323

| Rust change | C++ translation |
|---|---|
| Address PR comments. Code review feedback implementation. | **Translated** — Code review fixes — applied to our equivalent code. |

## Implementation details

- Code review fixes — applied to our equivalent code.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
