# Step 76 — "Resolved state is set as the current room state on incoming events" (Conduit `894b6ef`)

Source: [`timokoesters/conduit@894b6ef`](https://github.com/timokoesters/conduit/commit/894b6ef) (2021-01-28)

## What changed vs step 75

| Rust change | C++ translation |
|---|---|
| **Resolved state is set as current room state** | **Translated** — Set resolved state on incoming events |

## Implementation details

1. **Resolved state as current** — Set resolved state as the current room state on incoming events
2. **State resolution** — Improved state resolution handling

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
