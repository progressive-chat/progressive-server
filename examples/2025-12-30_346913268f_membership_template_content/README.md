# 2024/2025-tail — "fix: don't ignore content of membership template" (Conduit `346913268f`)

Source: [`timokoesters/conduit@346913268f`](https://github.com/timokoesters/conduit/commit/346913268f) (2025-12-30)

## What changed vs step 44 (last 2020 step)

| Rust change | C++ translation |
|---|---|
| Preserves custom fields in membership template content instead of overwriting entirely. | **Requires federation** — Preserves custom fields in membership template helper. |

## Implementation details

This fix preserves custom fields in the membership template content:

1. **Extracts existing content** from the template instead of creating new
2. **Preserves `join_authorized_via_users_server`** and other custom fields
3. **Merges new fields** (membership, displayname, avatar_url, blurhash, reason) into existing content
4. **Only adds fields that are present** (displayname, avatar_url, blurhash are optional)
5. **Removes manual `to_canonical_value` call** - content is built as CanonicalJsonObject

**Status:** Requires federation with `populate_membership_template` (step 82b7cf6). Our federation doesn't have this helper.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```