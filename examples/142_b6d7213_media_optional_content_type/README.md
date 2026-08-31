# Step 142 — "Have Media db return optional content_type, conversion fixes" (Conduit `b6d7213`)

Source: [`timokoesters/conduit@b6d7213`](https://github.com/timokoesters/conduit/commit/b6d7213) (2020-12)

## What changed vs step 141

| Rust change | C++ translation |
|---|---|
| Have Media db return optional content_type (was non-optional `String`). Conversion fixes for the new type. | **Translated** — Our `media_get` returns `database::Media::File` with optional content_type. Step 14 implements this. |

## Implementation details

- Our `media_get` returns `database::Media::File` with optional content_type. Step 14 implements this.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
