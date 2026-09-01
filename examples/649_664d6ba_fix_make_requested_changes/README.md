# Step 649 — "fix: make requested changes" (Conduit `664d6ba`)

Source: [`timokoesters/conduit@664d6ba`](https://github.com/timokoesters/conduit/commit/664d6ba) (2023-05)

## What changed vs step 648

| Rust change | C++ translation |
|---|---|
| Fix: make requested changes. Code review feedback implementation. | **Translated** — Code review fixes — applied to our equivalent code. |

## Implementation details

- Code review fixes — applied to our equivalent code.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
