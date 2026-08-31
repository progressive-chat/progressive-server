# Step 55 — "fix: put reason of redaction in the redacted event" (Conduit `3866322`)

Source: [`timokoesters/conduit@3866322`](https://github.com/timokoesters/conduit/commit/3866322) (2020-08)

## What changed vs step 54

| Rust change | C++ translation |
|---|---|
| Adds the `reason` field to redaction events. When you redact an event, the redaction event itself can carry a reason (e.g., "spam", "inappropriate"). | **Translated** — our redaction event (step 23, `18bf6774`) stores the event but doesn't include the `reason` field. This commit adds the `reason` to the redacted event content. |

## Implementation details

- **Translated** — our redaction event (step 23, `18bf6774`) stores the event but doesn't include the `reason` field. This commit adds the `reason` to the redacted event content.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
