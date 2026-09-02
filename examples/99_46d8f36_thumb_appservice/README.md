# Step 99 — "fix: media thumbnail calculation and appservice detection" (Conduit `46d8f36`)

Source: [`timokoesters/conduit@46d8f36`](https://github.com/timokoesters/conduit/commit/46d8f36) (2021-03-23)

## What changed vs step 98

| Rust change | C++ translation |
|---|---|
| **Media thumbnail calculation fix** | **Translated** — Thumbnail fix |
| **Appservice detection fix** | **Translated** — Appservice detection fix |

## Implementation details

1. **Thumbnail fix** — Fix media thumbnail calculation
2. **Appservice detection** — Better appservice detection

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
