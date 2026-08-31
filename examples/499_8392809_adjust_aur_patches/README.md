# Step 499 — "Adjust some files to the AUR patches" (Conduit `8392809`)

Source: [`timokoesters/conduit@8392809`](https://github.com/timokoesters/conduit/commit/8392809) (2022-05)

## What changed vs step 498

| Rust change | C++ translation |
|---|---|
| Adjust some files to the AUR patches. Arch Linux packaging adjustments. | **Skipped** — Packaging only. |

## Implementation details

- Packaging only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
