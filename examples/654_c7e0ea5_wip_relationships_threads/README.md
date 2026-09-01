# Step 654 — "feat: WIP relationships and threads" (Conduit `c7e0ea5`)

Source: [`timokoesters/conduit@c7e0ea5`](https://github.com/timokoesters/conduit/commit/c7e0ea5) (2023-06)

## What changed vs step 653

| Rust change | C++ translation |
|---|---|
| Feat: WIP relationships and threads. Message relationships and threads (MSC3440). 28 files changed. MAJOR feature. | **Translated** — We don't have threads yet. This adds MSC3440 relationships/threads. |

## Implementation details

- We don't have threads yet. This adds MSC3440 relationships/threads.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
