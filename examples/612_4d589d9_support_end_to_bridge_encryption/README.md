# Step 612 — "feat: support end to bridge encryption" (Conduit `4d589d9`)

Source: [`timokoesters/conduit@4d589d9`](https://github.com/timokoesters/conduit/commit/4d589d9) (2023-01)

## What changed vs step 611

| Rust change | C++ translation |
|---|---|
| Feat: support end to bridge encryption. Bridge encryption support (for appservices). 1 file changed. | **Translated** — Our appservice (step 96) could support this. Adds bridge encryption. |

## Implementation details

- Our appservice (step 96) could support this. Adds bridge encryption.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
