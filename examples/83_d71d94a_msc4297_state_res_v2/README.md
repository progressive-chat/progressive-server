# Step 83 — "feat: MSC4297, State Resolution v2.1" (Conduit `d71d94a`)

Source: [`timokoesters/conduit@d71d94a`](https://github.com/timokoesters/conduit/commit/d71d94a)

This step implements the **MSC4297 State Resolution v2.1** algorithm — a major rewrite of the state resolution logic used when merging state from different event branches (e.g., during room joins, syncs, and federation).

## What changed vs step 82

| Rust change | C++ translation |
|---|---|
| New `state_res` module with `get_conflicted_state_subgraph` | New `state_res` module with `get_conflicted_state_subgraph`, `resolve_state_v2`, topological sort |
| Auth event chain traversal for conflicted subgraph | Simplified conflicted subgraph detection (direct conflicts only) |
| Topological sorting of conflicted events | Basic topological sort by auth event dependencies |
| Canonical event ordering for deterministic resolution | First-in-topological-order wins for conflicts |

## What's implemented

- **New module**: `src/state_res.{hpp,cpp}` with `state_res` namespace
- **Conflicted subgraph detection**: Identifies events that are part of conflicted state paths
- **Topological sorting**: Orders events by auth event dependencies
- **State resolution v2**: `resolve_state_v2()` function that resolves conflicted state using topological ordering
- **Integration**: Added to `conduit_core` library via CMakeLists.txt

## Current limitations (simplified implementation)

- Auth event parsing from PDUs is stubbed (returns empty auth events)
- Conflicted subgraph detection only includes directly conflicted events (not full auth chain traversal)
- Topological sort is simplified (doesn't handle all edge cases)
- Canonical event ordering uses simplified first-in-topo-order wins

## Smoke test

```
POST /_matrix/client/r0/createRoom {}   -> 200 OK (room created)
GET /_matrix/client/r0/sync             -> 200 OK (sync works)
```

## Next steps for full MSC4297 compliance

1. Implement proper auth event extraction from PDUs
2. Full conflicted state subgraph traversal (traverse auth event chains)
3. Proper canonical event ordering per MSC4297 spec
4. Integration with event handler for incoming PDU validation
5. Handle server-side signature verification with new state resolution

This is a foundational step — the framework is in place for future MSC4297 compliance work.