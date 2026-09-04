# Step 85 — "State resolution outline for /send" (Conduit `d108a73`)

Source: [`timokoesters/conduit@d108a73`](https://github.com/timokoesters/conduit/commit/d108a73) (2021-02-09)

## What changed vs step 84

| Rust change | C++ translation |
|---|---|
| **State resolution outline for /send** | **Requires full state resolution** — Not yet implemented |

## Implementation details

This is another state resolution outline commit for the federation `/send` endpoint:

1. **State resolution outline** — More state resolution code in /send

**Status:** Requires full state resolution infrastructure (state_res crate equivalent) which is not yet implemented in C++. Our federation `/send` handler only has basic PDU storage.

**Note:** This is part of the major federation state resolution refactor that requires the complete state resolution infrastructure from step 93 (short ID system) and step 57 (state resolution basics).

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
