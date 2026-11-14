"""Local diagnostics and static configuration checks; no enforcement."""

import argparse
import importlib
import platform
import shutil
import sys


def _observe(collect):
    """Keep individual collection failures visible without losing the report."""
    try:
        value = collect()
        if not isinstance(value, str) or not value.strip():
            return "UNKNOWN", "collector returned no value"
        return "OBSERVED", value
    except Exception as error:
        # Exception messages can contain local paths or other private details.
        return "UNKNOWN", f"collection failed ({type(error).__name__})"


def collect_report():
    """Describe this Python process and local PATH, never a remote target."""
    system = _observe(platform.system)
    report = {
        "os": _observe(lambda: f"{system[1]} {platform.release()}")
        if system[0] == "OBSERVED" else system,
        "python": _observe(platform.python_version),
    }
    try:
        sqlite = importlib.import_module("sqlite3")
    except ModuleNotFoundError as error:
        report["sqlite"] = (
            ("ABSENT", "Python sqlite3 module or linked extension unavailable")
            if error.name in ("sqlite3", "_sqlite3")
            else ("UNKNOWN", "collection failed (ModuleNotFoundError)")
        )
    except Exception as error:
        report["sqlite"] = ("UNKNOWN", f"collection failed ({type(error).__name__})")
    else:
        report["sqlite"] = _observe(lambda: sqlite.sqlite_version)

    for tool in ("git", "ssh", "nginx", "nft"):
        if tool == "nft":
            if system[0] == "UNKNOWN":
                report[tool] = ("UNKNOWN", "OS unavailable; applicability unknown")
                continue
            if system[1] != "Linux":
                report[tool] = ("NOT_APPLICABLE", "Linux-only tool on a non-Linux development OS")
                continue
        try:
            report[tool] = (
                ("PRESENT", "discoverable on local PATH; execution not verified")
                if shutil.which(tool) else ("ABSENT", "not discoverable on local PATH")
            )
        except Exception as error:
            report[tool] = ("UNKNOWN", f"collection failed ({type(error).__name__})")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description="AegisControl local development diagnostics")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor", help="report read-only local development observations")
    config_check = commands.add_parser("config-check", help="validate an observe-only TOML file offline")
    config_check.add_argument("path", help="path to a development TOML configuration")
    replay = commands.add_parser("replay", help="summarize bounded synthetic JSONL offline")
    replay.add_argument("config", help="observe-only TOML configuration")
    replay.add_argument("input", help="synthetic JSONL fixture")
    replay.add_argument("--as-of", required=True, type=int, help="evaluation Unix UTC seconds")
    replay.add_argument("--max-age", type=int, default=60, help="freshness seconds, 1-86400")
    replay.add_argument("--route", action="append", help="exact origin path catalog (up to 32)")
    args = parser.parse_args(argv)
    if args.command == "replay":
        import json
        from .config import ConfigError, load_config
        from .replay import replay_file
        from .telemetry import TelemetryError
        try:
            config = load_config(args.config)
            report = replay_file(args.input, config, as_of=args.as_of,
                                 max_age=args.max_age, catalog=tuple(args.route or ("/",)))
        except (ConfigError, TelemetryError) as error:
            print(f"ERROR: {error}", file=sys.stderr)
            return 1
        print(json.dumps(report, sort_keys=True, allow_nan=False))
        return 0 if report["status"] == "COMPLETE" and report["coverage"] != "incomplete" else 1
    if args.command == "config-check":
        from .config import ConfigError, load_config
        try:
            config = load_config(args.path)
        except ConfigError as error:
            print(f"ERROR: {error}", file=sys.stderr)
            return 1
        print(f"Static observe configuration valid: {len(config.services)} service(s); enforcement disabled.")
        print("Targets and deployment readiness were not checked. Optional integrations are disabled.")
        if config.required_observations is not None:
            print(f"{len(config.required_observations)} required observation(s); coverage not assessed by config-check.")
        return 0
    report = collect_report()
    print("Scope: local development machine only; remote targets are not inspected.")
    print("Versions do not establish security patch compliance or target readiness.")
    for name, (status, detail) in report.items():
        print(f"{name}: {status} - {detail}")
    return 1 if any(status == "UNKNOWN" for status, _ in report.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
