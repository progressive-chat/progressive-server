# Step 138 — "fix: is_direct for locally invited users" (Conduit `deacdf6`)

Source: [`timokoesters/conduit@deacdf6`](https://github.com/timokoesters/conduit/commit/deacdf6) (2021-05-27)

Upstream sets `is_direct` on the invite content for locally invited users.

## What changed vs step 137

**Nothing in `src/` — this directory was a byte-identical copy.** Local
invite content has carried `is_direct` in this port since the invite flow
landed (verified again in modern step 122,
`122_ddcf1a71_redaction_send_receipts`), so there is nothing to change.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit138 && ./build/tests
```
