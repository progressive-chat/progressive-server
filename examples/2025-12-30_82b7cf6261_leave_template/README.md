# 2024/2025-tail — "fix: use populate_membership_template for `/leave`" (Conduit `82b7cf6261`)

Source: [`timokoesters/conduit@82b7cf6261`](https://github.com/timokoesters/conduit/commit/82b7cf6261) (2025-12-30)

## What changed vs step 44 (last 2020 step)

| Rust change | C++ translation |
|---|---|
| Uses `populate_membership_template` helper for `/leave` instead of manual event construction. Prevents event forgery. | **Requires federation** — Uses shared membership template helper for leave. |

## Implementation details

This commit refactors the remote leave flow to use `populate_membership_template`:

1. **Replaces manual event construction** with `populate_membership_template` helper
2. **Simplifies leave event creation**: No manual canonical JSON manipulation, event ID generation, or hashing
3. **Passes reason parameter** through to the template
4. **Uses `MembershipState::Leave`** in the template
5. **Adds required fields** in helper: `type`, `sender`, `state_key` (added in helpers/mod.rs)

**Status:** Requires federation implementation (step 29+). Our federation doesn't have this helper.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```