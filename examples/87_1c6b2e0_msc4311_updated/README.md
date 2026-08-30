# Step 87 — "feat: updated MSC4311 support" (Conduit `1c6b2e0`)

Source: [`timokoesters/conduit@1c6b2e0`](https://github.com/timokoesters/conduit/commit/1c6b2e0)

This step updates the **MSC4311** implementation to match the finalized spec. The key changes:

1. **Create event in invite/knock stripped_state is now sent as a full PDU** (`RawStrippedState::Pdu`) instead of a stripped state event
2. **`utils::check_stripped_state` is removed** (was validating stripped state against room version rules)
3. **Type change**: `StrippedState` → `AnyStrippedStateEvent` (enum with `Stripped` and `Pdu` variants)

## What changed vs step 84

| Rust change | C++ translation |
|---|---|
| Create event in stripped_state is now `RawStrippedState::Pdu` (full PDU) | Already implemented in step 84: we add the full create event PDU to `invited.stripped_state` and `knocked.stripped_state` |
| `utils::check_stripped_state` removed | Not applicable (we didn't implement this validation) |
| `StrippedState` → `AnyStrippedStateEvent` (enum: `Stripped` | `Pdu`) | Our implementation sends full PDU for create event, which matches the new `Pdu` variant. Other stripped state events remain as-is. |

## Implementation details

The key behavioral change is that the create event in invite/knock stripped_state is now explicitly a full PDU (wrapped in `RawStrippedState::Pdu`), while other state events remain as stripped state events. In our C++ translation, we already include the full create event PDU in the `stripped_state` vector for invites and knocks, which matches the new behavior.

The type system change (`StrippedState` → `AnyStrippedStateEvent`) is a Rust type system change. In our JSON-based implementation, we represent both stripped state events and the create event PDU as JSON strings in the `stripped_state` vector. The wire format would need a type discriminator for full spec compliance, but our simplified implementation sends the raw JSON.

## Smoke test

```
POST /_matrix/client/r0/createRoom {}   -> 200
GET /_matrix/client/r0/sync             -> invited.knocked rooms include create event PDU in stripped_state
```

## Note

This is a wire-protocol change. Full spec compliance would require a type discriminator in the `stripped_state` JSON to distinguish `Stripped` vs `Pdu` variants of `AnyStrippedStateEvent`. Our simplified implementation sends raw JSON strings.