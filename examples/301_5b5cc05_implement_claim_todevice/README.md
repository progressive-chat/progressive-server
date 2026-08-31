# Step 301 — "feat: implement /claim, handle to-device events" (Conduit `5b5cc05`)

Source: [`timokoesters/conduit@5b5cc05`](https://github.com/timokoesters/conduit/commit/5b5cc05) (2021-05)

## What changed vs step 300

| Rust change | C++ translation |
|---|---|
| Feat: implement /claim, handle to-device events. Key claiming and to-device messaging (for encryption). 8 files changed. MAJOR feature. | **Translated** — We don't have /claim or to-device events yet. This adds encryption key claiming. |

## Implementation details

- We don't have /claim or to-device events yet. This adds encryption key claiming.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
