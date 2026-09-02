# Step 128 — "improvement: federation get_keys and optimize signingkey storage" (Conduit `09157b2`)

Source: [`timokoesters/conduit@09157b2`](https://github.com/timokoesters/conduit/commit/09157b2) (2021-05-21)

## What changed vs step 127

| Rust change | C++ translation |
|---|---|
| **Get encryption keys over federation** | **Translated** — Federation key fetching |
| **Optimize signing key storage** | **Translated** — Signing key optimization |
| **Rate limit bad events** | **Translated** — Event rate limiting |
| **Major server_server refactor** | **Translated** — Cleaner server_server |
| **Major keys.rs refactor** | **Translated** — Cleaner keys code |

## Implementation details

1. **Get encryption keys over federation** — Get encryption keys over federation
2. **Optimize signing key storage** — Optimize signing key storage
3. **Rate limit bad events** — Rate limit parsing of bad events
4. **Major server_server refactor** — Major refactor of server_server
5. **Major keys refactor** — Major refactor of keys.rs

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
