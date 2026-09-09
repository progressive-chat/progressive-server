# AGENTS.md — instructions for coding agents working in this repo

## Build parallelism from available RAM (mandatory)

C++ builds here are memory-hungry (RocksDB + heavy TUs). Before every
`make`/`cmake --build`, check available RAM and pick parallelism accordingly.
Use **MemAvailable** from `/proc/meminfo` (not the `free` column of `free`).

| Available RAM | Action |
|---|---|
| < 1.5 GB | DO NOT build. Sleep and re-check in a loop until ≥ 1.5 GB is available. |
| 1.5 GB – < 3 GB | Build with `-j1` |
| 3 GB – < 4.5 GB | Build with `-j2` |
| ≥ 4.5 GB | Build with `-j3` (never higher in this repo) |

Shell snippet (run before building; waits when RAM is scarce):

```bash
while :; do
  avail_kb=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
  avail_gb=$((avail_kb / 1024 / 1024))
  if [ "$avail_gb" -lt 1 ]; then
    echo "Only ${avail_gb}GB available (<1.5GB), waiting 60s..."
    sleep 60
  else
    break
  fi
done
avail_gb=$(($(awk '/^MemAvailable:/ {print $2}' /proc/meminfo) / 1024 / 1024))
if [ "$avail_gb" -ge 4 ]; then jobs=3
elif [ "$avail_gb" -ge 3 ]; then jobs=2
elif [ "$avail_gb" -ge 1 ]; then jobs=1
else jobs=1
fi
make -j"$jobs" -C build   # or: cmake --build build -j"$jobs"
```

Notes:
- Re-check RAM right before each build invocation; other agents/jobs may
  compete for memory between steps.
- Full fresh builds take ~20 min; incremental builds ~3–5 min.
- Keep `/tmp` usage in check (`tmpfs` is small): remove stale `/tmp/test*`
  database dirs and helper binaries when done.
