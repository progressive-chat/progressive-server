# Step 702 — "Admin commands to sign and verify jsons" (Conduit `da90745`)

Source: [`timokoesters/conduit@da90745`](https://github.com/timokoesters/conduit/commit/da90745) (2023-07)

## What changed vs step 701

| Rust change | C++ translation |
|---|---|
| Admin commands to sign and verify jsons. JSON signing/verification admin commands. 1 file changed. | **Translated** — Our admin commands (step 60) don't have sign/verify. This adds them. |

## Implementation details

- Our admin commands (step 60) don't have sign/verify. This adds them.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
