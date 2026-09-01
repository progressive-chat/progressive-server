# Step 658 — "Add relations endpoints, edits and threads work now" (Conduit `72eb197`)

Source: [`timokoesters/conduit@72eb197`](https://github.com/timokoesters/conduit/commit/72eb197) (2023-06)

## What changed vs step 657

| Rust change | C++ translation |
|---|---|
| Add relations endpoints, edits and threads work now. Relations API (MSC3440) implementation. 8 files changed. MAJOR feature. | **Translated** — Follows step 654 (relationships/threads WIP). This adds the relations endpoints. |

## Implementation details

- Follows step 654 (relationships/threads WIP). This adds the relations endpoints.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
