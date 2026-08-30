# Step 91 — "refactor(service/admin): improve readability for command processing" (Conduit `470e477`)

Source: [`timokoesters/conduit@470e477`](https://github.com/timokoesters/conduit/commit/470e477)

This step refactors Conduit's room-based admin command parser to improve readability. Changes include removing `Either` usage, improving formatting, and minor logic adjustments to the `AllowRegistration` command.

## What changed vs step 89

| Rust change | C++ translation |
|---|---|
| Code style improvements (removing `Either`, better formatting) | **No-op** — our admin uses HTTP endpoints, not room-based commands |
| `AllowRegistration` logic simplification | Not applicable (we use `POST /_conduit/admin/register` HTTP endpoint) |

## Implementation details

Our admin subsystem uses HTTP endpoints (`/_conduit/admin/*`), not room-based commands. The Conduit refactor is purely internal to their room-based command parser and has no equivalent in our HTTP-based admin API.

## Smoke test

No behavioral change — admin HTTP endpoints continue to work as before.