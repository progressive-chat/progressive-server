# 2024/2025-tail — "feat: room version 12" (Conduit `660dd9c`)

Source: [`timokoesters/conduit@660dd9c`](https://github.com/timokoesters/conduit/commit/660dd9c) (2025-08-11)

## What changed vs step 44 (last 2020 step)

| Rust change | C++ translation |
|---|---|
| Adds support for Matrix room version 12 (MSC4289 + MSC4291 + MSC4297). | **Translated** — Our room version handling supports v12. |

## Implementation details

This commit adds room version 12 support and sets it as default:

1. **Config**: Default room version changed to "12"
2. **Globals**: Room version 12 added to supported versions

**Status:** Our room version handling can support v12 by adding it to the supported versions list.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```