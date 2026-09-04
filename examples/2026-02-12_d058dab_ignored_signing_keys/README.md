# 2026-tail — "feat: add option to ignore specific server signing keys" (Conduit `d058dab`)

Source: [`timokoesters/conduit@d058dab`](https://github.com/timokoesters/conduit/commit/d058dab) (2026-02-12)

## What changed vs step 93 (last numbered step)

| Rust change | C++ translation |
|---|---|
| Adds `ignored_server_signing_keys` config option to skip validating keys from specific servers. | **Not implemented** — No config layer for ignored signing keys |

## Implementation details

This would require:
1. Config option for `ignored_server_signing_keys` 
2. Check in signature verification to skip listed servers

**Status:** Not implemented — no config layer for ignored signing keys

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```