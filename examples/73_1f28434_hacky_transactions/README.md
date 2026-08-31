# Step 73 — "feat: hacky transactions" (Conduit `1f28434`)

Source: [`timokoesters/conduit@1f28434`](https://github.com/timokoesters/conduit/commit/1f28434) (2020-09)

## What changed vs step 72

| Rust change | C++ translation |
|---|---|
| Adds the `/_matrix/federation/v1/send/{txnId}` federation transaction endpoint. A remote server delivers PDUs to us via this endpoint. | **Translated** — our step 30 (`1f292c09_federation_send`) implements this endpoint. |

## Implementation details

- **Translated** — our step 30 (`1f292c09_federation_send`) implements this endpoint.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
