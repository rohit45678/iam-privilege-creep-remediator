#!/usr/bin/env python3
"""IAM Privilege-Creep Remediator CLI.

Usage:
    python main.py [--policies sample_data/policies.json]
                   [--usage sample_data/usage_log.csv]
                   [--out out/]

Reads IAM-style policies plus a 90-day usage log, writes a findings report
(``findings.json``) and one tightened least-privilege policy per identity
(``policies/<identity>.json``) into the output directory, and prints a
human-readable summary.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from iam_remediator import analyzer, generator, loaders, report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policies", default="sample_data/policies.json",
                        help="path to the policies JSON file")
    parser.add_argument("--usage", default="sample_data/usage_log.csv",
                        help="path to the usage log CSV file")
    parser.add_argument("--out", default="out/",
                        help="output directory for the report and policies")
    args = parser.parse_args(argv)

    identities = loaders.load_policies(args.policies)
    usage = loaders.load_usage(args.usage)

    analyses = analyzer.analyze(identities, usage)
    generated = [
        generator.generate_policy(identity, usage.get(identity["name"], {}))
        for identity in identities
    ]

    full_report = report.build_report(analyses, generated)

    policies_dir = os.path.join(args.out, "policies")
    os.makedirs(policies_dir, exist_ok=True)
    with open(os.path.join(args.out, "findings.json"), "w", encoding="utf-8") as fh:
        json.dump(full_report, fh, indent=2)
    for gen in generated:
        path = os.path.join(policies_dir, f"{gen['identity']}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(gen, fh, indent=2)

    print(report.render_summary(full_report), end="")
    print(f"Report written to {os.path.join(args.out, 'findings.json')}")
    print(f"Tightened policies written to {policies_dir}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
