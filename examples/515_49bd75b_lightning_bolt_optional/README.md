# Step 515 — "Lightning bolt optional" (Conduit `49bd75b`)

Source: [`timokoesters/conduit@49bd75b`](https://github.com/timokoesters/conduit/commit/49bd75b) (2022-06)

## What changed vs step 514

| Rust change | C++ translation |
|---|---|
| Lightning bolt optional. Feature flag for some optional functionality. 5 files changed. | **Translated** — Feature flag — our build doesn't have this specific flag. |

## Implementation details

- Feature flag — our build doesn't have this specific flag.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
