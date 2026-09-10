# Step 802 — "fix: don't apply push rules for users of other homeservers" (Conduit `e1e529d8`)

Source: [`timokoesters/conduit@e1e529d8`](https://github.com/timokoesters/conduit/commit/e1e529d8) (2021-05-30)

Straight-order intermediates with no C++ behavior change: `59dd3676`
(type-annotation-only fix), `88cf043f` (password `Option` + Rust-argon
migration for wrongly-hashed empty passwords — the C++ empty-string
convention already covers this).

## What changed vs step 122

| Rust change | C++ translation |
|---|---|
| **Push evaluation only for same-server users** | **Implemented** — the `pdu_append` count-bump loop skips members whose server suffix isn't ours |
| **Skip deactivated users** | **Implemented** — `is_deactivated(member)` skips counting (alongside the existing sender skip) |
| **Drive-by fix: orphaned deactivate route** | **Fixed** — `POST /account/deactivate` had a handler with no route registration (unreachable); re-registered (needed to exercise deactivation live) |
| **Drive-by** | Removed an unused `sender_local` variable in the same loop |

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server
```
