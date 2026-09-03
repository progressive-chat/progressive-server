# Step 338: ada07de2 - feat: support user password resets

**Conduit commit:** `ada07de2`
**Category:** Admin feature

## Summary

feat: support user password resets

## C++ Translation

This commit adds support for user password resets via admin commands.

### Changes:
- **data.cpp (admin_process_message)**: Added "resetpassword <username>" admin command that:
  1. Parses the username (case-insensitive, adds @domain if needed)
  2. Validates user exists and is not deactivated
  3. Prevents resetting the conduit user
  4. Generates a random 20-character password
  5. Uses `set_password()` to hash and store the new password
  6. Logs the new password for the admin

This mirrors Conduit's `AdminCommand::ResetPassword` implementation.

**Status:** Real implementation (not a placeholder).

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```