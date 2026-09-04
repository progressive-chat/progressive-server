# Step 702 — "Admin commands to sign and verify jsons" (Conduit `da90745`)

Source: [`timokoesters/conduit@da90745`](https://github.com/timokoesters/conduit/commit/da90745) (2023-07)

## What changed vs step 701

| Rust change | C++ translation |
|---|---|
| Admin commands to sign and verify jsons. JSON signing/verification admin commands. 1 file changed. | **Requires admin infrastructure** — Our admin commands don't have sign/verify yet. |

## Implementation details

This Conduit commit adds two admin commands:

1. **SignJson**: Signs a JSON object with the server's signing key
   - Accepts JSON in a code block (```json```)
   - Uses `ruma::signatures::sign_json` with server keypair
   - Returns the signed JSON

2. **VerifyJson**: Verifies a JSON object's signatures
   - Accepts JSON in a code block
   - Fetches required signing keys via `fetch_required_signing_keys`
   - Uses `ruma::signatures::verify_json` to verify
   - Returns "Signature correct" or error

**Status:** Requires admin command infrastructure (step 60+) and JSON signing utilities. Our implementation doesn't have `ruma::signatures` equivalent.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```