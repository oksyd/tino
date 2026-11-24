#!/usr/bin/env python3

import argparse
import json
import pathlib
import urllib.parse
import urllib.request


USER_AGENT = "tino/update-seccomp-landlock"
REQUEST_TIMEOUT_SECONDS = 30


def fetch_json(url: str) -> dict:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/vnd.github+json",
        },
    )
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
        return json.load(resp)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Refresh seccomp-landlock.json from moby/profiles default seccomp profile."
    )
    parser.add_argument(
        "--ref",
        default="main",
        help="Git ref for moby/profiles (default: main).",
    )
    args = parser.parse_args()

    repo_root = pathlib.Path(__file__).resolve().parent.parent

    ref = urllib.parse.quote(args.ref, safe="")
    commit = fetch_json(f"https://api.github.com/repos/moby/profiles/commits/{ref}")
    sha = commit["sha"]

    profile = fetch_json(
        f"https://raw.githubusercontent.com/moby/profiles/{sha}/seccomp/default.json"
    )

    missing = {
        "landlock_add_rule",
        "landlock_create_ruleset",
        "landlock_restrict_self",
    }

    syscalls = profile.setdefault("syscalls", [])
    for rule in syscalls:
        if rule.get("action") == "SCMP_ACT_ALLOW" and not any(
            rule.get(key) for key in ("args", "includes", "excludes")
        ):
            missing.difference_update(rule.get("names") or ())

    if missing:
        syscalls.append(
            {
                "names": sorted(missing),
                "action": "SCMP_ACT_ALLOW",
                "comment": "Allow Landlock syscalls for tino access restrictions",
            }
        )

    profile_path = repo_root / "seccomp-landlock.json"
    sha_path = repo_root / "seccomp-landlock.upstream.sha"

    with profile_path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(profile, handle, indent=2)
        handle.write("\n")
    with sha_path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(f"{sha}\n")

    print(f"Wrote {profile_path} from moby/profiles@{sha}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
