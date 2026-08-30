# Step 94 — "fix: don't perform identity assertion on appservice-only endpoints" (Conduit `98e2bed`)

Source: [`timokoesters/conduit@98e2bed`](https://github.com/timokoesters/conduit/commit/98e2bed)

This step fixes appservice authentication to only accept `AuthScheme::AppserviceToken` for appservice tokens (not `AuthScheme::AccessToken`).

## What changed vs step 92

| Rust change | C++ translation |
|---|---|
| Only accept `AuthScheme::AppserviceToken` for appservice tokens | **Already implemented** — our `appservice_id_from_token` only matches hs_tokens from the `appservice_token_id` tree |

## Implementation details

Our appservice ping endpoint (`/_matrix/client/v1/appservice/{id}/ping`) uses `appservice_id_from_token` which only matches tokens stored in the `appservice_token_id` tree (hs_tokens). This is equivalent to only accepting `AppserviceToken` scheme.

## Smoke test

No behavioral change — appservice ping continues to work correctly.