# Step 143 — "create media folder in init" (Conduit `affa124`)

Source: [`timokoesters/conduit@affa124`](https://github.com/timokoesters/conduit/commit/affa124) (2021-06-09)

Upstream creates the media directory during database initialization.

## What changed vs step 142

**Nothing in `src/` — this directory was a byte-identical copy.** The
modern chain's `Media::set_dir()` already creates the directory
(`std::filesystem::create_directories`), and step 803 wires it to
`<data_dir>/media/` at startup — so the folder is created on init.

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DHTTPLIB_USE_ZSTD_IF_AVAILABLE=OFF -DFETCHCONTENT_BASE_DIR=/home/user/deps-cache && cmake --build build -j
$ ./build/server --port 8000 --data-dir /tmp/conduit143 && ./build/tests
```
