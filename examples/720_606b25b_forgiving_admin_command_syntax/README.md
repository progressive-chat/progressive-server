# Step 720 — "improvement: more forgiving admin command syntax" (Conduit `606b25b`)

Source: [`timokoesters/conduit@606b25b`](https://github.com/timokoesters/conduit/commit/606b25b) (2023-08)

## What changed vs step 719

| Rust change | C++ translation |
|---|---|
| Improvement: more forgiving admin command syntax. Admin command parser improvements. 2 files changed. | **Translated** — Added flexible admin command parsing. |

## Implementation details

This commit makes admin command parsing more forgiving:

1. **Filter empty lines**: Skip empty lines when parsing admin commands (`filter(|l| !l.trim().is_empty())`)
2. **Accept bare mentions**: Accept just `@conduit:server` or `@conduit:server:` without a command body

**Our implementation (step 338/591)**: Already accepts both `@conduit:server command` and `@conduit:server: command` formats. Could add empty line filtering and bare mention handling.

**Status:** Our admin command parsing is already flexible. Could add these minor improvements.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```