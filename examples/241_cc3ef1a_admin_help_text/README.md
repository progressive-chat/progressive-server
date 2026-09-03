# Step 241 — "Improve help text for admin commands" (Conduit `cc3ef1a`)

Source: [`timokoesters/conduit@cc3ef1a`](https://github.com/timokoesters/conduit/commit/cc3ef1a) (2022-01-21)

## What changed vs step 240

| Rust change | C++ translation |
|---|---|
| **Admin commands help text** | **Translated** — Admin help text |

## Implementation details

1. **Admin help text** — Improve help text for admin commands

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
