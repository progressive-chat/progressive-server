# Step 78 — "feat: download media and thumbnails over federation" (Conduit `aa5e9e6`)

Source: [`timokoesters/conduit@aa5e9e6`](https://github.com/timokoesters/conduit/commit/aa5e9e6) (2020-09)

## What changed vs step 77

| Rust change | C++ translation |
|---|---|
| Adds federation media endpoints: `/_matrix/federation/v1/media/download/{server}/{id}` and `/thumbnail/{server}/{id}`. Remote servers can fetch media from us. | Our step 33 (`aa5e9e60_fed_media`) implements these endpoints. |

## Implementation details

- Our step 33 (`aa5e9e60_fed_media`) implements these endpoints.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
