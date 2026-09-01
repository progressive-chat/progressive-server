# Step 716 — "Avatars for sliding sync DMs" (Conduit `d82c26f`)

Source: [`timokoesters/conduit@d82c26f`](https://github.com/timokoesters/conduit/commit/d82c26f) (2023-08)

## What changed vs step 715

| Rust change | C++ translation |
|---|---|
| Avatars for sliding sync DMs. Sliding sync avatar support for direct messages. 4 files changed. | **Translated** — Follows step 670/689/690 (sliding sync). Adds avatar support for DMs. |

## Implementation details

- Follows step 670/689/690 (sliding sync). Adds avatar support for DMs.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
