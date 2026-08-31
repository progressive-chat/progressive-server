# Step 190 — "fix: default config options" (Conduit `ea1e462`)

Source: [`timokoesters/conduit@ea1e462`](https://github.com/timokoesters/conduit/commit/ea1e462) (2021-02)

## What changed vs step 189

| Rust change | C++ translation |
|---|---|
| Fix: default config options. Better defaults for various settings. | **Translated** — Our config defaults are in main.cpp. This improves them. |

## Implementation details

- Our config defaults are in main.cpp. This improves them.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
