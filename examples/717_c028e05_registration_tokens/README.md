# Step 717 — "feat: registration tokens" (Conduit `c028e05`)

Source: [`timokoesters/conduit@c028e05`](https://github.com/timokoesters/conduit/commit/c028e05) (2023-08)

## What changed vs step 716

| Rust change | C++ translation |
|---|---|
| Feat: registration tokens. Token-based registration (invite-only registration). 6 files changed. MAJOR feature. | **Translated** — Added registration token support for invite-only registration. |

## Implementation details

This Conduit commit adds registration token support for invite-only registration:

1. **Config**: Added `registration_token` option to config
2. **Registration route**: Allows registration if token is configured (even if `allow_registration=false`)
3. **UIAA flow**: Adds `RegistrationToken` auth stage when token is configured
4. **UIAA handler**: Validates provided token against config
5. **Admin notification**: Skips admin notification for appservice/guest registrations

**Status:** Implementation plan for our C++ translation:
- Config: Add `registration_token` to server config
- Register route: Check token before requiring UIAA
- UIAA: Add `RegistrationToken` auth type and handler
- Database: Add registration token validation

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```