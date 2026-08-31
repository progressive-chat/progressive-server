# Step 445 — "Resolve merge conflict" (Conduit `1cc0b55`)

Source: [`timokoesters/conduit@1cc0b55`](https://github.com/timokoesters/conduit/commit/1cc0b55) (2022-02)

## What changed vs step 444

| Rust change | C++ translation |
|---|---|
| Resolve merge conflict. Code merge resolution. 8 files changed. | **Translated** — Merge conflict resolution — applied to our equivalent code. |

## Implementation details

- Merge conflict resolution — applied to our equivalent code.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
