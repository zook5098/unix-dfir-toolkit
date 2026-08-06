#!/usr/bin/env python3
"""normalize_uac.py

Reads a UAC (https://github.com/tclahr/uac) output folder -- or the
tar/tar.gz archive UAC produces directly, which is extracted to a temp
directory first -- and normalizes a first-slice set of artifacts into this
toolkit family's common schema (same fields windows-dfir-toolkit's
normalize_kape.py emits):
    timestamp, host, artifact_type, action, detail, source_file

v1 scope, matching collection/artifacts.md's default ir_triage profile:
    - shell history (bash/zsh/sh) -> action=shell_command
    - auth logs (auth.log/secure, sshd + sudo lines) -> action=auth_event
    - process listing (ps-style output) -> action=process_running

UAC's own file layout under an artifact's output directory can shift
between versions, so files are matched by filename pattern + content
sniffing rather than an exact fixed path, and a file that doesn't match any
known pattern is skipped with a note on stderr rather than failing the run.

Usage:
    python normalize_uac.py --input <uac_output_dir_or_archive> --output normalized.csv --host HOSTNAME
"""

import argparse
import csv
import os
import re
import shutil
import sys
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path


NORMALIZED_FIELDS = ["timestamp", "host", "artifact_type", "action", "detail", "source_file"]

HISTORY_FILENAME_RE = re.compile(r"(bash_history|zsh_history|sh_history|mysql_history|history)$", re.IGNORECASE)
AUTHLOG_FILENAME_RE = re.compile(r"(auth\.log|secure|sudo)", re.IGNORECASE)
PROCESS_FILENAME_RE = re.compile(r"(^|_)(ps|process(es)?)(_|\.|$)", re.IGNORECASE)

# Classic syslog timestamp: "Jan 12 03:04:05". No year -- callers must supply
# one (UAC's own collection-run year is used here as a best-effort default,
# since syslog itself doesn't record it and log rotation means "current
# year" alone can be wrong for older entries).
SYSLOG_TS_RE = re.compile(r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<proc>\S+?):\s*(?P<msg>.*)$")

SSHD_ACCEPTED_RE = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
SSHD_FAILED_RE = re.compile(r"Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
SUDO_COMMAND_RE = re.compile(r"(?P<user>\S+)\s*:.*COMMAND=(?P<command>.*)")


def _parse_syslog_timestamp(ts_text, fallback_year):
    try:
        parsed = datetime.strptime(f"{fallback_year} {ts_text}", "%Y %b %d %H:%M:%S")
        return parsed.isoformat()
    except ValueError:
        return ts_text


def extract_if_archive(input_path):
    """If input_path is a UAC tar/tar.gz archive, extract to a temp dir and return that dir.

    Otherwise return input_path unchanged. Caller is responsible for cleaning
    up the temp dir (returned alongside a flag) once done.
    """
    path = Path(input_path)
    if path.is_dir():
        return path, None

    if tarfile.is_tarfile(path):
        temp_dir = Path(tempfile.mkdtemp(prefix="uac_extract_"))
        with tarfile.open(path) as tf:
            tf.extractall(temp_dir)  # nosec - operator-supplied local UAC output, not untrusted input
        return temp_dir, temp_dir

    sys.exit(f"error: {input_path} is neither a directory nor a recognized tar archive.")


def parse_history_file(path, host):
    """Shell history files rarely carry timestamps (HISTTIMEFORMAT is opt-in and not
    exported by default), so the file's own mtime is used as a best-effort
    timestamp for every line and flagged as such -- it reflects "last write to
    this history file", not the time each individual command ran."""
    mtime = datetime.fromtimestamp(path.stat().st_mtime).isoformat()
    records = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as e:
        print(f"[skip] could not read {path}: {e}", file=sys.stderr)
        return []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        records.append(
            {
                "timestamp": mtime,
                "artifact_type": "shell_history",
                "action": "shell_command",
                "detail": f"{line} [timestamp=file_mtime, not command time]",
                "host": host,
                "source_file": str(path),
            }
        )
    return records


def parse_authlog_file(path, host):
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as e:
        print(f"[skip] could not read {path}: {e}", file=sys.stderr)
        return []

    fallback_year = datetime.fromtimestamp(path.stat().st_mtime).year
    records = []
    for line in lines:
        m = SYSLOG_TS_RE.match(line)
        if not m:
            continue
        timestamp = _parse_syslog_timestamp(m.group("ts"), fallback_year)
        proc = m.group("proc")
        msg = m.group("msg")

        if "sshd" in proc:
            accepted = SSHD_ACCEPTED_RE.search(msg)
            failed = SSHD_FAILED_RE.search(msg)
            if accepted:
                detail = f"user={accepted.group('user')} src_ip={accepted.group('ip')} method={accepted.group('method')}"
                action = "ssh_login_success"
            elif failed:
                detail = f"user={failed.group('user')} src_ip={failed.group('ip')} method={failed.group('method')}"
                action = "ssh_login_failed"
            else:
                continue
        elif "sudo" in proc:
            cmd = SUDO_COMMAND_RE.search(msg)
            if not cmd:
                continue
            detail = f"user={cmd.group('user')} command={cmd.group('command')}"
            action = "sudo_command"
        else:
            continue

        records.append(
            {
                "timestamp": timestamp,
                "artifact_type": "auth_log",
                "action": action,
                "detail": detail,
                "host": host,
                "source_file": str(path),
            }
        )
    return records


def parse_process_file(path, host):
    """ps-style listing: header row + whitespace-delimited columns. No event
    timestamp exists in a process snapshot, so the file's mtime (collection
    time) is used and flagged, matching the history-file convention above."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as e:
        print(f"[skip] could not read {path}: {e}", file=sys.stderr)
        return []
    if not lines:
        return []

    header = lines[0].split()
    if not header:
        return []
    pid_idx = next((i for i, col in enumerate(header) if col.upper() in ("PID",)), None)
    cmd_idx = next((i for i, col in enumerate(header) if col.upper() in ("CMD", "COMMAND", "ARGS")), None)
    if pid_idx is None or cmd_idx is None:
        return []

    collected_at = datetime.fromtimestamp(path.stat().st_mtime).isoformat()
    records = []
    for line in lines[1:]:
        parts = line.split(None, max(pid_idx, cmd_idx))
        if len(parts) <= max(pid_idx, cmd_idx):
            continue
        pid = parts[pid_idx]
        cmd = parts[-1] if cmd_idx == len(header) - 1 else parts[cmd_idx]
        records.append(
            {
                "timestamp": collected_at,
                "artifact_type": "process",
                "action": "process_running",
                "detail": f"pid={pid} cmd={cmd} [timestamp=collection_time]",
                "host": host,
                "source_file": str(path),
            }
        )
    return records


def classify_and_parse(path, host):
    name = path.name
    if HISTORY_FILENAME_RE.search(name):
        return parse_history_file(path, host)
    if AUTHLOG_FILENAME_RE.search(name):
        return parse_authlog_file(path, host)
    if PROCESS_FILENAME_RE.search(name):
        return parse_process_file(path, host)
    return None


def normalize_dir(root_dir, host):
    rows = []
    matched_files = 0
    for path in sorted(Path(root_dir).rglob("*")):
        if not path.is_file():
            continue
        result = classify_and_parse(path, host)
        if result is None:
            continue
        matched_files += 1
        rows.extend(result)
    return rows, matched_files


def main():
    parser = argparse.ArgumentParser(description="Normalize a UAC output folder/archive into the common schema.")
    parser.add_argument("--input", required=True, help="UAC output directory, or its tar/tar.gz archive")
    parser.add_argument("--output", required=True, help="Output CSV path")
    parser.add_argument("--host", required=True, help="Hostname to tag records with")
    args = parser.parse_args()

    root_dir, temp_dir = extract_if_archive(args.input)
    try:
        rows, matched_files = normalize_dir(root_dir, args.host)
    finally:
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)

    if matched_files == 0:
        print(f"No recognized artifact files found under {args.input}", file=sys.stderr)

    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=NORMALIZED_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} normalized rows from {matched_files} matched files to {args.output}")


if __name__ == "__main__":
    main()
