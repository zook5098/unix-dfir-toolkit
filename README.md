# Unix DFIR Toolkit

Automated collection and normalization of Unix-like host artifacts for
rapid incident response triage. Companion to
[windows-dfir-toolkit](https://github.com/zook5098/windows-dfir-toolkit),
covering Linux/macOS/*BSD/Solaris hosts the way that repo covers Windows.

## Relationship to UAC

Collection itself is handled by
[UAC (Unix-like Artifacts Collector)](https://github.com/tclahr/uac), not
custom-built collectors. This toolkit is a thin wrapper + normalization
layer around it, the same role `windows-dfir-toolkit` plays around KAPE:
`collection/run_uac.py` invokes `uac` (installed/cloned separately, not
vendored — see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)) with a
curated profile/artifact set, and `parsers/normalize_uac.py` reads UAC's
output and normalizes it into a common schema.

## Architecture

```
collection/   -> run_uac.py wraps uac with a curated profile/artifact set for IR triage
                 artifacts.md documents which UAC profile/artifacts are used and why
parsers/      -> normalize_uac.py reads UAC's output folder/archive and normalizes
                 recognized artifacts into a common schema:
                 timestamp, host, artifact_type, action, detail, source_file
```

`timeline/` (merge + ATT&CK tagging + dashboard, matching
`windows-dfir-toolkit`'s pipeline) is planned once artifact coverage here
is broader than the v1 slice below — the normalized CSV schema is
deliberately identical to that repo's so the same timeline tooling can
eventually run against either.

## Artifacts covered (v1 scope)

| Artifact | Source | What it reveals |
|---|---|---|
| Shell history | `.bash_history`, `.zsh_history`, `.sh_history` | Commands run, though only the file's last-write time, not per-command time — see caveat below |
| Auth logs | `/var/log/auth.log`, `/var/log/secure` (sshd + sudo lines) | SSH login success/failure, sudo command execution |
| Process listing | UAC's `ps`-style live-response output | Running processes at collection time |

Everything else UAC collects under the default `ir_triage` profile (network
state, cron/systemd persistence, system info, etc.) is gathered on disk in
the run's output folder but not yet parsed into the common schema —
`normalize_uac.py` skips unrecognized files rather than failing. See
[collection/artifacts.md](collection/artifacts.md) for the full profile
description and how to broaden or narrow what's collected.

## Pipeline

1. **Collect** — `collection/run_uac.py` invokes `uac` (assumed
   installed/cloned and on `PATH`, or passed via `--uac-path`) against a
   live host or, with `--offline-image`, a mounted image.
2. **Normalize** — `parsers/normalize_uac.py` reads UAC's output
   directory (or its tar/tar.gz archive directly) and normalizes
   recognized artifacts into the common schema.

## Quick start

**Prerequisites:**

- **A Unix-like collection target** — Linux, macOS, or a *BSD/Solaris host
  UAC supports. `run_uac.py` itself runs anywhere Python 3 does (including
  Windows, e.g. to drive collection against a mounted image or over SSH),
  but `uac` itself needs to execute on/against a Unix-like target.
- **Root/sudo on the target** for a live-host run — most live-response
  artifacts (process, network, memory-adjacent info) need it. Not required
  for `--offline-image` collection against a mounted, already-acquired
  filesystem.
- **[UAC](https://github.com/tclahr/uac)** — cloned separately and on
  `PATH`, or pass `--uac-path /path/to/uac`.
- **Python 3.8+** — stdlib only, no extra packages required for either
  script (`requirements.txt` is empty on purpose; kept as a placeholder for
  when `timeline/` lands and needs `pyyaml`, matching
  `windows-dfir-toolkit`).

```bash
git clone https://github.com/zook5098/unix-dfir-toolkit
cd unix-dfir-toolkit

# Collect with UAC's ir_triage profile (curated live-response set)
# --case-name should identify the subject system/case, not your own analysis machine
sudo python3 collection/run_uac.py --output-dir /tmp/triage --case-name CASE-2026-014

# ...or a different bundled profile
sudo python3 collection/run_uac.py --output-dir /tmp/triage --case-name CASE-2026-014 --profile full

# ...or collect from a mounted image instead of a live host
python3 collection/run_uac.py --output-dir /tmp/triage --case-name CASE-2026-014 \
    --offline-image /mnt/evidence --offline-system linux

# Full usage
python3 collection/run_uac.py --help

# Normalize UAC's output (folder or its tar/tar.gz archive) into the common schema
python3 parsers/normalize_uac.py --input /tmp/triage/CASE-2026-014_<timestamp> --output ./case001/normalized.csv --host HOSTNAME
```

## Known limitations (v1)

- **Shell history has no per-command timestamp.** `HISTTIMEFORMAT` isn't
  exported by default, so `normalize_uac.py` timestamps every history line
  with the file's own last-modified time and marks each row
  `[timestamp=file_mtime, not command time]` rather than silently implying
  precision that isn't there.
- **UAC's on-disk file layout can shift between versions.** Artifacts are
  matched by filename pattern + light content sniffing, not a fixed path.
  A file that doesn't match a known pattern is skipped with a note on
  stderr — it's still in the collected output, just not yet normalized.

## Roadmap

- [x] UAC-based collection wrapper (`collection/run_uac.py`)
- [x] UAC output normalizer, v1 slice: shell history, auth logs, process listing (`parsers/normalize_uac.py`)
- [ ] Broaden normalizer coverage: network state, cron/systemd persistence, package/binary inventory
- [ ] Timeline merge + ATT&CK tagging (`timeline/`, mirroring `windows-dfir-toolkit`)
- [ ] SQLite-backed timeline dashboard, ported from `windows-dfir-toolkit/timeline/`

## Design principles

- **Minimal footprint on live systems** — UAC collects read-only from the
  source; this wrapper writes nothing to the target host itself beyond
  what UAC's own output-format flag controls.
- **Chain of custody friendly** — UAC logs what it collected; keep the
  run's output folder (and `run_uac.py`'s per-run `.log` file) as the
  evidence record.
- **Same normalized schema as `windows-dfir-toolkit`** — so a shared
  timeline pipeline can eventually merge Windows and Unix host artifacts
  from a mixed-platform incident into one timeline.

## Status

Early build — collection and a first normalization slice are scaffolded.
See Roadmap above for current coverage.

## License

[MIT](LICENSE). See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for
the external tool this repo wraps.
