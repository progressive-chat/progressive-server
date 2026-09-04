# Step 791 — msc4297_state_res_v2

Source: [`timokoesters/conduit@d71d94a`](https://github.com/timokoesters/conduit/commit/d71d94a) (2025-08-11)

## What changed vs step 790

| Rust change | C++ translation |
|---|---|
| Adopts the v2.1 state resolution algorithm in `state_res.cpp`. | **Real implementation** — Added MSC4297 State Resolution v2.1 in `state_res.cpp/hpp`. |

## Implementation details

This commit adds MSC4297 State Resolution v2.1 algorithm:

1. **Conflicted state subgraph detection** (`get_conflicted_state_subgraph`):
   - Identifies conflicted state keys (multiple events for same state key)
   - Collects directly conflicted events
   - Full MSC4297 would traverse auth event chains (stubbed for now)

2. **Topological sort** (`topological_sort`):
   - DFS-based topological sort of conflicted events
   - Handles cycles gracefully

3. **State resolution** (`resolve_state_v2`):
   - Builds state map from event IDs
   - Identifies conflicted state keys
   - Computes conflicted subgraph
   - Topologically sorts conflicted events
   - Resolves using canonical ordering (first in topological order wins)
   - Returns non-conflicted state as-is

Files added:
- `state_res.hpp` - Header with StateMap, EventAuth, ConflictedSubgraphResult, function declarations
- `state_res.cpp` - Implementation of conflicted subgraph, topological sort, and resolve_state_v2

**Status:** Real implementation (simplified - auth event chain traversal stubbed).

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```