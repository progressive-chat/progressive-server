# 2024/2025-tail — "fix: use append_member_pdu for `/invite`" (Conduit `3db42bd`)

Source: [`timokoesters/conduit@3db42bd`](https://github.com/timokoesters/conduit/commit/3db42bd) (2025-12-22)

## What changed vs step 44 (last 2020 step)

| Rust change | C++ translation |
|---|---|
| Adds `federation::handle_member_pdu` helper for room-version-aware join/invite/knock handling. | **Requires federation** — Refactors invite handling to use shared `handle_member_pdu` with room version rules. |

## Implementation details

This refactors the federation invite/join handling:

1. **New `handle_member_pdu` function**: Replaces `append_member_pdu`, handles Join/Invite/Knock with room version rules
2. **Passes room version rules** directly instead of looking them up
3. **Uses `AuthorizationRules`** from room version for checks
4. **Invite handling**: If membership is Invite, no appending is done (done over `/send` instead)
5. **Restricted join check**: Uses `rules.authorization` for restricted join checks
6. **Sign join event**: Logic updated to use rules for redaction

**Status:** Requires federation implementation (step 29+). Our federation doesn't have this refactoring.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```