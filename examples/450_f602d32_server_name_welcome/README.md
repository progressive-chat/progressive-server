# Step 450 — "feat: add the actual server name to the welcome message" (Conduit `f602d32`)

Source: [`timokoesters/conduit@f602d32`](https://github.com/timokoesters/conduit/commit/f602d32) (2022-02)

## What changed vs step 449

| Rust change | C++ translation |
|---|---|
| Feat: add the actual server name to the welcome message. Welcome message includes server name. | **Translated** — Our welcome message could include server name. Minor UX improvement. |

## Implementation details

- Our welcome message could include server name. Minor UX improvement.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
