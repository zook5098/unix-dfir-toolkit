#!/usr/bin/env python3
"""run_uac.py

Wrapper around UAC (Unix-like Artifacts Collector, https://github.com/tclahr/uac)
that runs a curated profile/artifact set for IR triage, the same role
run_kape.ps1 plays for KAPE on the Windows side of this toolkit family.

UAC is a shell script (`uac`), not a Python package — it is assumed to
already be cloned/installed on the collection host (or reachable over SSH
for a remote pull) and is invoked, not vendored. See collection/artifacts.md
for the default profile/artifact set and how to override it.

Output is written under a per-run, timestamped case folder so repeat runs
against the same host never clobber prior evidence:
    <OutputDir>/<CaseName>_<timestamp>/

Usage:
    sudo python3 run_uac.py --output-dir /tmp/triage --case-name CASE-2026-014
    sudo python3 run_uac.py --output-dir /tmp/triage --case-name CASE-2026-014 \\
        --profile full
    sudo python3 run_uac.py --output-dir /tmp/triage --case-name CASE-2026-014 \\
        --artifacts live_response/process,live_response/network,files/bash_history
    python3 run_uac.py --output-dir /tmp/triage --case-name CASE-2026-014 \\
        --offline-image /mnt/evidence --offline-system linux

Run with --help for full option details.
"""

import argparse
import datetime
import os
import shutil
import subprocess
import sys


DEFAULT_PROFILE = "ir_triage"


def build_parser():
    parser = argparse.ArgumentParser(
        description="Wrapper around UAC that runs a curated artifact set for IR triage.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Root folder for UAC output. A per-run, timestamped subfolder is created under this path.",
    )
    parser.add_argument(
        "--case-name",
        required=True,
        help=(
            "Case/incident identifier used in the output folder name and passed to UAC's "
            "--case-number. Required -- deliberately has no default, since the analyst's own "
            "machine is very often not the subject system, especially in --offline-image mode."
        ),
    )
    profile_group = parser.add_mutually_exclusive_group()
    profile_group.add_argument(
        "--profile",
        default=DEFAULT_PROFILE,
        help=f"UAC profile to run (default: {DEFAULT_PROFILE}). See collection/artifacts.md.",
    )
    profile_group.add_argument(
        "--artifacts",
        help="Comma-separated UAC artifact list to collect instead of a profile (passed to uac -a).",
    )
    parser.add_argument(
        "--offline-image",
        help=(
            "Path to a mounted disk image / offline filesystem to collect from, instead of the "
            "live host. Passed through to uac's offline-collection flags -- verify the exact "
            "flag names for your UAC version with 'uac -h', they have changed across releases."
        ),
    )
    parser.add_argument(
        "--offline-system",
        help="OS type of the offline target (e.g. linux, macos). Required by UAC when --offline-image is used.",
    )
    parser.add_argument(
        "--output-format",
        default="tar",
        choices=["tar", "zip", "none"],
        help="UAC output format (default: tar), passed to uac -o.",
    )
    parser.add_argument(
        "--uac-path",
        default="uac",
        help="Path to the uac script. Defaults to 'uac', resolved via PATH.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the uac command that would run, without executing it.",
    )
    return parser


def resolve_uac(path):
    resolved = shutil.which(path)
    if not resolved:
        sys.exit(
            f"error: uac not found at '{path}' or on PATH. Clone https://github.com/tclahr/uac "
            "and pass --uac-path /path/to/uac, or add it to PATH."
        )
    return resolved


def main():
    args = build_parser().parse_args()

    if args.offline_image and not args.offline_system:
        sys.exit("error: --offline-system is required when --offline-image is given.")

    if not args.offline_image and os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() != 0:
        print(
            "WARNING: not running as root. UAC needs root to collect most live-response "
            "artifacts (process, network, memory-adjacent info) on a live host; artifacts it "
            "can't read will simply be skipped, not fail the whole run.",
            file=sys.stderr,
        )

    uac_exe = args.uac_path if args.dry_run and not shutil.which(args.uac_path) else resolve_uac(args.uac_path)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    run_name = f"{args.case_name}_{timestamp}"
    run_dir = os.path.join(args.output_dir, run_name)

    if not args.dry_run:
        os.makedirs(run_dir, exist_ok=True)

    uac_args = [uac_exe]
    if args.artifacts:
        uac_args += ["-a", args.artifacts]
        artifact_mode = "custom artifact list"
    else:
        uac_args += ["-p", args.profile]
        artifact_mode = "profile"
    uac_args += ["-o", args.output_format]
    uac_args += ["--case-number", args.case_name]
    if args.offline_image:
        uac_args += ["--offline-image", args.offline_image, "--offline-system", args.offline_system]
    uac_args += [run_dir]

    print(f"uac binary    : {uac_exe}")
    print(f"Artifact mode : {artifact_mode} ({args.artifacts or args.profile})")
    print(f"Output format : {args.output_format}")
    print(f"Output dir    : {run_dir}")
    if args.offline_image:
        print(f"Offline image : {args.offline_image} ({args.offline_system})")

    if args.dry_run:
        print("Dry run -- command not executed:")
        print(" ".join(uac_args))
        return

    log_path = os.path.join(args.output_dir, f"{run_name}.log")
    with open(log_path, "w", encoding="utf-8") as log_file:
        result = subprocess.run(uac_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        log_file.write(result.stdout or "")
        print(result.stdout or "")

    if result.returncode != 0:
        sys.exit(f"uac exited with code {result.returncode}. See {log_path} for details.")

    collected = [f for f in os.listdir(run_dir)] if os.path.isdir(run_dir) else []
    if not collected:
        print(
            f"WARNING: uac exited cleanly but {run_dir} contains no output files. "
            f"Check {log_path} for errors (e.g. an unrecognized profile/artifact name).",
            file=sys.stderr,
        )

    print(f"Done. Output: {run_dir}")
    print(f"Log: {log_path}")


if __name__ == "__main__":
    main()
