# Step 21 — "feat: account deactivation" (Conduit `b8193984`, 2020-07-05, PR #137)

Source: [`timokoesters/conduit@b8193984`](https://github.com/timokoesters/conduit/commit/b8193984)

## What changed vs step 20

| Rust change | C++ translation |
|---|---|
| `POST /account/deactivate` with UIAA `m.login.password` | route added; wrong password → 403 M_FORBIDDEN |
| leaves all joined rooms + rejects invitations via member leave events | same, through pdu_append |
| `Users::deactivate_account` — removes all devices, blanks password (empty string = deactivated marker) | identical convention |
| login to deactivated account → M_USER_DEACTIVATED "The user has been deactivated" | identical errcode/message |
| user_directory/search filters out deactivated users | same filter |

## Verified

```
no auth            → 401 {flows:[m.login.password]}
wrong pw           → 403 M_FORBIDDEN
correct pw         → 200 {id_server_unbind_result:"no-support"}
old token          → 401
login after        → 403 M_USER_DEACTIVATED
```
