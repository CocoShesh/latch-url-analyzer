#!/usr/bin/env python3
"""Small JSON adapter for DNSTwist's passive permutation mode."""
import contextlib
import io
import json
import sys


def main():
    try:
        import dnstwist
    except Exception:
        print(json.dumps({"ok": False, "error": "Python package dnstwist is not installed"}))
        return 2

    if len(sys.argv) == 2 and sys.argv[1] == "--check":
        print(json.dumps({"ok": True}))
        return 0
    if len(sys.argv) != 2:
        print(json.dumps({"ok": False, "error": "Expected one registrable domain"}))
        return 2

    # The list format generates permutations only. It performs no DNS, HTTP,
    # WHOIS, SMTP, screenshot, or page-similarity checks.
    output = io.StringIO()
    try:
        with contextlib.redirect_stdout(output):
            variants = dnstwist.run(domain=sys.argv[1], format="list")
        print(json.dumps({"ok": True, "variants": variants or []}))
        return 0
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)[:300]}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
