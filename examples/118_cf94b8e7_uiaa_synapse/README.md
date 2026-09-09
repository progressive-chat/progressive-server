# Step 118 — "improvement: uiaa works like in synapse" (Conduit `cf94b8e7`)

Source: [`timokoesters/conduit@cf94b8e7`](https://github.com/timokoesters/conduit/commit/cf94b8e7) (2021-05-04)

## What changed vs step 117

| Rust change | C++ translation |
|---|---|
| **UIAA sessions keyed by user+device+session** | **Implemented** — `userdeviceid_uiaainfo` key layout extended with the session id; `create`/`update`/`get` take the session |
| **Original auth request stored per session** | **Implemented** — new `userdevicesessionid_uiaarequest` tree + `set_uiaa_request` / `get_uiaa_request` |
| **`try_auth` creates the session on first use (Synapse behavior)** | **Implemented** — unknown session starts a fresh flow instead of failing; request stored alongside |

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server
```
