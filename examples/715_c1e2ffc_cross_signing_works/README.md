# Step 715 — "improvement: maybe cross signing really works now" (Conduit `c1e2ffc`)

Source: [`timokoesters/conduit@c1e2ffc`](https://github.com/timokoesters/conduit/commit/c1e2ffc) (2023-08)

## What changed vs step 714

| Rust change | C++ translation |
|---|---|
| Improvement: maybe cross signing really works now. Cross-signing (E2EE key verification) implementation. 7 files changed. MAJOR. | **Translated** — We don't have cross-signing yet. This adds cross-signing (E2EE key verification). |

## Implementation details

This Conduit commit implements cross-signing (E2EE key verification):

1. **Cross-signing keys**: Master, user signing, and self-signing keys
2. **Key upload/download**: Endpoints for managing cross-signing keys
3. **Key verification**: Device verification via cross-signing
4. **Signature verification**: Verifies signatures on device keys
5. **Trust establishment**: Users can verify other users' devices

**Status:** Major E2EE feature. Our implementation doesn't have cross-signing or E2EE yet.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```