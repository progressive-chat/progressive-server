# Step 252 — "fix: signature mismatch on odd send_join servers" (Conduit `a5f004d`)

Source: [`timokoesters/conduit@a5f004d`](https://github.com/timokoesters/conduit/commit/a5f004d) (2022-02-02)

## What changed vs step 251

| Rust change | C++ translation |
|---|---|
| **Signature mismatch on send_join** | **Translated** — Signature mismatch send_join |

## Implementation details

1. **Signature mismatch send_join** — Fix signature mismatch on odd send_join servers

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
