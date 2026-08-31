# Step 449 — "feat: add 'available' to the help command line in the welcome message" (Conduit `a6976e6`)

Source: [`timokoesters/conduit@a6976e6`](https://github.com/timokoesters/conduit/commit/a6976e6) (2022-02)

## What changed vs step 448

| Rust change | C++ translation |
|---|---|
| Feat: add 'available' to the help command line in the welcome message. Welcome message help text. | **Translated** — Continuation of step 448 — more welcome message improvements. |

## Implementation details

- Continuation of step 448 — more welcome message improvements.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
