# Step 718 — "fix: don't show removed rooms in space" (Conduit `1835581`)

Source: [`timokoesters/conduit@1835581`](https://github.com/timokoesters/conduit/commit/1835581) (2023-08)

## What changed vs step 717

| Rust change | C++ translation |
|---|---|
| Fix: don't show removed rooms in space. Space hierarchy excludes removed rooms. 1 file changed. | **Requires step 667** — Excludes rooms with `via` in space child event (rooms accessible via other servers). |

## Implementation details

This fix filters out space children that have a `via` field in their `m.space.child` event content. Rooms with `via` are accessible via other servers (not directly in this space), so they shouldn't appear in the local space hierarchy.

**Status:** Requires step 667 (space hierarchies). Would filter children in `space_children` or hierarchy traversal.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```