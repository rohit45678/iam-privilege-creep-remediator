"""Findings report assembly and human-readable summary rendering."""

from __future__ import annotations


def build_report(analyses, generated_policies):
    """Combine per-identity analyses and generated policies into one report."""
    generated_by_identity = {g["identity"]: g for g in generated_policies}
    identities = []
    for analysis in analyses:
        entry = dict(analysis)
        entry["generated_policy"] = generated_by_identity[analysis["identity"]]["policy"]
        identities.append(entry)

    total_unused = sum(len(a["unused_permissions"]) for a in analyses)
    total_escalation = sum(len(a["escalation_risks"]) for a in analyses)
    critical = sum(
        1
        for a in analyses
        for f in a["findings"]
        if f["severity"] == "critical"
    )
    return {
        "tool": "iam-privilege-creep-remediator",
        "usage_window_days": 90,
        "summary": {
            "identities_analyzed": len(analyses),
            "unused_permissions_total": total_unused,
            "escalation_capable_grants_total": total_escalation,
            "critical_findings": critical,
            "highest_risk_identity": analyses[0]["identity"] if analyses else None,
        },
        "identities": identities,
    }


def render_summary(report):
    """Render the report as a plain-text summary for the CLI."""
    lines = []
    summary = report["summary"]
    lines.append("IAM Privilege-Creep Remediation Report")
    lines.append("=" * 60)
    lines.append(f"Identities analyzed : {summary['identities_analyzed']}")
    lines.append(f"Unused permissions  : {summary['unused_permissions_total']}")
    lines.append(f"Escalation grants   : {summary['escalation_capable_grants_total']}")
    lines.append(f"Critical findings   : {summary['critical_findings']}")
    lines.append("")
    for entry in report["identities"]:
        lines.append(
            f"{entry['identity']} ({entry['cloud']}/{entry['type']}) "
            f"- risk score {entry['risk_score']}"
        )
        lines.append(
            f"  granted patterns: {len(entry['granted_patterns'])} | "
            f"used actions: {len(entry['used_actions'])} | "
            f"unused permissions: {len(entry['unused_permissions'])}"
        )
        for finding in entry["findings"]:
            lines.append(f"  [{finding['severity'].upper()}] {finding['detail']}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
