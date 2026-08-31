# Step 510 — "feat: more admin commands, better logging" (Conduit `9b89824`)

Source: [`timokoesters/conduit@9b89824`](https://github.com/timokoesters/conduit/commit/9b89824) (2022-06)

## What changed vs step 509

| Rust change | C++ translation |
|---|---|
| Feat: more admin commands, better logging. Admin command expansion and logging improvements. 8 files changed. MAJOR. | **Translated** — Our admin commands (step 60) are basic. This adds more commands and better logging. |

## Implementation details

- Our admin commands (step 60) are basic. This adds more commands and better logging.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
