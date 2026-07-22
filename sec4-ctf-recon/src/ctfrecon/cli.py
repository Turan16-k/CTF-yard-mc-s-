"""
CTF recon CLI.

  python -m ctfrecon.cli file <dosya> [--json rapor.json]
  python -m ctfrecon.cli web  <url>

Yetkili hedefler / CTF pratigi icindir.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

from .analyzers import run_all
from .web import recon


def analyze_file(path: str, json_out: str | None) -> int:
    with open(path, "rb") as f:
        data = f.read()
    findings = run_all(data)
    print(f"=== Dosya recon: {path} ({len(data)} bayt) ===")
    for fnd in findings:
        print(f"[{fnd.module}] {fnd.title}: {fnd.detail}")
    if json_out:
        with open(json_out, "w", encoding="utf-8") as jf:
            json.dump([asdict(f) for f in findings], jf, ensure_ascii=False, indent=2)
        print(f"\nRapor kaydedildi: {json_out}")
    return 0


def analyze_web(url: str) -> int:
    print(f"=== Web recon: {url} ===")
    for f in recon(url):
        print(f"[web] {f.title}: {f.detail}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="CTF recon yardimcisi")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_file = sub.add_parser("file", help="dosya analizi")
    p_file.add_argument("path")
    p_file.add_argument("--json", default=None)

    p_web = sub.add_parser("web", help="web recon")
    p_web.add_argument("url")

    args = ap.parse_args(argv)
    if args.cmd == "file":
        return analyze_file(args.path, args.json)
    if args.cmd == "web":
        return analyze_web(args.url)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
