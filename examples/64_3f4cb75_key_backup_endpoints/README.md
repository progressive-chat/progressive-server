# Step 64 — "improvement: add remaining key backup endpoints" (Conduit `3f4cb75`)

Source: [`timokoesters/conduit@3f4cb75`](https://github.com/timokoesters/conduit/commit/3f4cb75) (2020-08)

## What changed vs step 63

| Rust change | C++ translation |
|---|---|
| Adds the remaining key backup endpoints: `/room_keys/keys/{roomId}/{sessionId}`, delete room key, etc. Extends the key backup store from step 27. | **Translated** — our step 27 (`3f4cb753_key_backup`) implements the full set of key backup endpoints. |

## Implementation details

- **Translated** — our step 27 (`3f4cb753_key_backup`) implements the full set of key backup endpoints.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
