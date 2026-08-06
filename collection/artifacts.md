# UAC artifact/profile selection

[UAC (Unix-like Artifacts Collector)](https://github.com/tclahr/uac) ships its
own curated **profiles** (named sets of artifacts) and individual
**artifacts** (one shell script + YAML definition each, organized by
category under `artifacts/` in the UAC repo). `run_uac.py` doesn't
reimplement any of that — it just picks a profile/artifact set to pass
through on `uac`'s own `-p`/`-a` flags.

Exact profile and artifact names vary by UAC version — run `./uac -h` or
`./uac --list-profiles` / `--list-artifacts` against your checkout to see
what's actually bundled before relying on the defaults below. As of recent
UAC releases, the profiles most relevant to IR triage are:

| Profile | What it collects | When to use |
|---|---|---|
| `ir_triage` | Curated live-response set: process list, network connections, logged-in users, cron/systemd persistence, shell history, auth logs | Default for `run_uac.py` — fast, high-signal, matches this toolkit's "small core" scope |
| `offline` | Same artifact set as `ir_triage` but skips artifacts that require executing live-system commands (e.g. `ps`, `netstat`) — safe for a **mounted disk image**, not a live host | Use `--offline` when collecting from a mounted/read-only image rather than a running system |
| `full` | Everything UAC supports | Broad parity collection; much slower and noisier — not the default here |
| `logs` | Log files only (auth, syslog, journal, application logs) | Log-focused triage, e.g. brute-force/lateral-movement investigations |
| `network` | Network configuration and live connection state | Network-focused triage |

## Default artifact set (`ir_triage` profile)

The `ir_triage` profile is the default because it lines up with this
toolkit's initial scope: system info, processes, network, logs, users, and
shell history — the same slice `windows-dfir-toolkit` starts from on the
Windows side (Prefetch/EventLogs/Registry/Amcache as the closest
equivalents). Individual artifact categories it pulls from (names per the
UAC artifact tree, subject to the version caveat above):

- `live_response/process` — running processes, open files, loaded modules
- `live_response/network` — listening ports, established connections, routing/ARP tables
- `live_response/system` — hostname, kernel/OS version, uptime, mounted filesystems, logged-in/last-logged-in users
- `files/bash_history` (and other shell history: zsh, sh, mysql, etc.)
- `files/logs` — `/var/log/auth.log`, `/var/log/secure`, syslog, `journalctl` export where present
- `files/cron` and systemd unit listings — persistence

## Overriding the default

Pass `--artifacts` to `run_uac.py` with a comma-separated UAC artifact list
to collect a custom set instead of a profile, or `--profile <name>` to use a
different bundled profile (e.g. `full`, `logs`, `network`). `--artifacts`
takes precedence over `--profile` when both are given, same as
`-CompoundTarget`/`-Targets` precedence in `run_kape.ps1` on the Windows
side.
