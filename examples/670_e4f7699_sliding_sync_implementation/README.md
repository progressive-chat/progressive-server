# Step 670 — "feat: very simple sliding sync implementation" (Conduit `e4f7699`)

Source: [`timokoesters/conduit@e4f7699`](https://github.com/timokoesters/conduit/commit/e4f7699) (2023-07)

## What changed vs step 669

| Rust change | C++ translation |
|---|---|
| Feat: very simple sliding sync implementation. Sliding sync (MSC3575) for efficient /sync. 12 files changed. MAJOR feature. | **Translated** — We don't have sliding sync yet. This adds MSC3575 sliding sync. |

## Implementation details

- We don't have sliding sync yet. This adds MSC3575 sliding sync.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
