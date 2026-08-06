# Third-Party Notices

This repository does not vendor any third-party code. It wraps and
normalizes output from the following external tool, which must be
installed/cloned separately:

## UAC (Unix-like Artifacts Collector)

- **What**: A live-response artifact collection shell script for
  AIX, Android, ESXi, FreeBSD, Linux, macOS, NetBSD, NetScaler, OpenBSD,
  and Solaris. `collection/run_uac.py` invokes it (`uac`) rather than
  reimplementing collection logic.
- **Source**: https://github.com/tclahr/uac
- **License**: Apache License 2.0
- **Not vendored**: install/clone UAC separately per its own instructions
  and point `run_uac.py` at it with `--uac-path`, or add `uac` to `PATH`.
