# Step 20 — "implement password changing" (Conduit `67a1f21f`, 2020-07-02, PR #138)

Source: [`timokoesters/conduit@67a1f21f`](https://github.com/timokoesters/conduit/commit/67a1f21f)

## What changed vs step 15 (logout)

| Rust change | C++ translation |
|---|---|
| `POST /account/password` with UIAA `m.login.password` stage | route added; wrong current password → 403 M_FORBIDDEN |
| `Users::set_password` — Argon2id rehash and store | `Data::set_password` via `utils::calculate_hash` |
| logout all devices EXCEPT current one | iterates `all_device_ids`, skips bound device, calls `remove_device` |

Also folded: `remove_device(user, device)` public wrapper (upstream
`users.rs remove_device`) for direct device removal.

## Verified

```
no auth          → 401 {flows:[m.login.password]}
wrong current pw → 403 M_FORBIDDEN
correct pw       → 200; other device's token invalidated [401];
                   current token still works [200]
new password     → login works; old password rejected
```
