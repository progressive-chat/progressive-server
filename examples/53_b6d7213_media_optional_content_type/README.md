# Step 53 — "Have Media db return optional content_type, conversion fixes" (Conduit `b6d7213`)

Source: [`timokoesters/conduit@b6d7213`](https://github.com/timokoesters/conduit/commit/b6d7213) (2020-12-05)

## What changed vs step 52

| Rust change | C++ translation |
|---|---|
| **Media::File content_type: String → Option<String>** | **Translated** — Updated File struct |
| **Media::get returns Option<File> with optional content_type** | **Translated** — Updated get method signature |
| **to_canonical_object utility function** | **Translated** — Added canonical JSON conversion |
| **Media get_thumbnail uses content_type directly** | **Translated** — Updated thumbnail response |
| **Canonical JSON conversion for PDUs** | **Translated** — Use canonical JSON for hashing |

## Implementation details

1. **Media::File**: `content_type` field changed from `String` to `Option<String>`
2. **Media::get**: Returns `Option<File>` where `File::content_type` is `Option<String>`
3. **to_canonical_object**: Added utility for canonical JSON conversion
4. **Media get_thumbnail**: Returns content_type directly (not wrapped in Some)
5. **Canonical JSON for PDUs**: Used for hashing/signing

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
