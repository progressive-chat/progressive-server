# Step 448 — "feat: add a line with the help command to the welcome message" (Conduit `f2b8aa2`)

Source: [`timokoesters/conduit@f2b8aa2`](https://github.com/timokoesters/conduit/commit/f2b8aa2) (2022-02)

## What changed vs step 447

| Rust change | C++ translation |
|---|---|
| Feat: add a line with the help command to the welcome message. Welcome message improvement. | **Translated** — Our welcome message could include help. Minor UX improvement. |

## Implementation details

- Our welcome message could include help. Minor UX improvement.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
