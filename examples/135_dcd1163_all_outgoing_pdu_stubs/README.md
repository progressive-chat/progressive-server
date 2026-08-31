# Step 135 — "All outgoing pdus in Sending must be PduStubs" (Conduit `dcd1163`)

Source: [`timokoesters/conduit@dcd1163`](https://github.com/timokoesters/conduit/commit/dcd1163) (2020-12)

## What changed vs step 134

| Rust change | C++ translation |
|---|---|
| All outgoing PDUs in the Sending struct must be PduStubs (a wrapper type for outgoing federation events). | **Translated** — Our `federation_send_to_remotes` sends JSON-serialized PDUs directly. The PduStub wrapper is a Rust type for type safety that doesn't apply to our JSON-based C++ implementation. |

## Implementation details

- Our `federation_send_to_remotes` sends JSON-serialized PDUs directly. The PduStub wrapper is a Rust type for type safety that doesn't apply to our JSON-based C++ implementation.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
