# Step 131 — "improvement: warning for small max_request_size values" (Conduit `1b42770`)

Source: [`timokoesters/conduit@1b42770`](https://github.com/timokoesters/conduit/commit/1b42770) (2021-05-22)

Upstream prints an error at startup when the configured `max_request_size`
is below 1 KB.

## What changed vs step 130

**Nothing in `src/` — this directory was a byte-identical copy.** The commit
is a three-line startup warning for a TOML config key this port does not
have: there is no request-size limit (and hence no small value to warn
about), so there is nothing to translate.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit131 && ./build/tests
```
