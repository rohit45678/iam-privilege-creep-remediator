"""Privilege-creep analysis.

For each identity the analyzer compares granted permission patterns with
observed usage and produces:

* ``unused``           - concrete granted actions never used in the window
* ``wildcard_grants``  - granted patterns containing ``*``
* ``escalation_risks`` - granted privilege-escalation-capable actions
* ``findings``         - human-readable findings with severities
* ``risk_score``       - deterministic score used to rank identities

Risk score composition (documented so results are reproducible):

* full-admin grant (``Action: "*"``) ......... +50
* unused escalation-capable action .......... +10 each
* used escalation-capable action ............ +5 each
* wildcard grant ............................ +3 each
* unused concrete permission ................ +1 each
"""

from __future__ import annotations

# Actions that let a principal escalate its own privileges or assume a more
# privileged identity. AWS entries follow the usual CIS / PMapper lists;
# GCP entries are the service-account impersonation / IAM-policy write set.
ESCALATION_ACTIONS = frozenset(
    {
        # AWS
        "iam:PassRole",
        "iam:CreatePolicyVersion",
        "iam:SetDefaultPolicyVersion",
        "iam:AttachUserPolicy",
        "iam:AttachRolePolicy",
        "iam:PutUserPolicy",
        "iam:PutRolePolicy",
        "iam:UpdateAssumeRolePolicy",
        "iam:CreateAccessKey",
        "sts:AssumeRole",
        # GCP
        "iam.serviceAccounts.actAs",
        "iam.serviceAccounts.getAccessToken",
        "resourcemanager.projects.setIamPolicy",
    }
)


def is_wildcard(pattern):
    """True if a granted action pattern contains a ``*`` wildcard."""
    return "*" in pattern


def pattern_matches(pattern, action):
    """True if granted ``pattern`` covers concrete ``action``.

    Supports the IAM pattern shapes ``*``, ``service:*`` and
    ``service:Prefix*`` plus exact matches.
    """
    if pattern == "*":
        return True
    if pattern.endswith("*"):
        return action.startswith(pattern[:-1])
    return pattern == action


def granted_patterns(identity):
    return [g["action"] for g in identity["granted"]]


def is_granted(identity, action):
    """True if ``action`` is covered by any granted pattern."""
    return any(pattern_matches(p, action) for p in granted_patterns(identity))


def analyze_identity(identity, usage_for_identity):
    """Analyze one identity against its observed usage.

    ``usage_for_identity`` is the per-identity mapping produced by
    :func:`iam_remediator.loaders.load_usage` (``{}`` when the identity
    never appears in the log).
    """
    patterns = granted_patterns(identity)
    used_actions = set(usage_for_identity)

    concrete_granted = {p for p in patterns if not is_wildcard(p)}
    unused = sorted(a for a in concrete_granted if a not in used_actions)
    wildcards = sorted({p for p in patterns if is_wildcard(p)})
    full_admin = "*" in wildcards

    escalation_risks = []
    for action in sorted(ESCALATION_ACTIONS):
        granting = sorted({p for p in patterns if pattern_matches(p, action)})
        if granting:
            used = action in used_actions
            escalation_risks.append(
                {
                    "action": action,
                    "granted_via": granting,
                    "used": used,
                    "severity": "high" if used else "critical",
                }
            )

    # Usage of actions that no grant covers is an anomaly worth surfacing.
    ungranted_usage = sorted(a for a in used_actions if not is_granted(identity, a))

    risk_score = 0
    if full_admin:
        risk_score += 50
    risk_score += 10 * sum(1 for e in escalation_risks if not e["used"])
    risk_score += 5 * sum(1 for e in escalation_risks if e["used"])
    risk_score += 3 * len(wildcards)
    risk_score += len(unused)

    findings = []
    if full_admin:
        findings.append(
            {
                "type": "full_admin",
                "severity": "critical",
                "detail": "Identity holds a full-administrator grant (Action: '*').",
            }
        )
    if not used_actions and patterns:
        findings.append(
            {
                "type": "dormant_identity",
                "severity": "high",
                "detail": "Identity has grants but zero observed usage in the window.",
            }
        )
    for risk in escalation_risks:
        findings.append(
            {
                "type": "escalation_capable",
                "severity": risk["severity"],
                "detail": (
                    f"{risk['action']} is granted via {', '.join(risk['granted_via'])} "
                    f"and was {'used' if risk['used'] else 'never used'} in the window."
                ),
            }
        )
    for pattern in wildcards:
        if pattern != "*":
            findings.append(
                {
                    "type": "wildcard_grant",
                    "severity": "medium",
                    "detail": f"Wildcard grant '{pattern}' covers more actions than observed usage.",
                }
            )
    if unused:
        findings.append(
            {
                "type": "unused_permissions",
                "severity": "medium",
                "detail": f"{len(unused)} granted permission(s) never used: {', '.join(unused)}.",
            }
        )
    for action in ungranted_usage:
        findings.append(
            {
                "type": "usage_without_grant",
                "severity": "high",
                "detail": f"Action {action} was used successfully but is not covered by any grant.",
            }
        )

    return {
        "identity": identity["name"],
        "type": identity["type"],
        "cloud": identity["cloud"],
        "granted_patterns": sorted(set(patterns)),
        "used_actions": sorted(used_actions),
        "unused_permissions": unused,
        "wildcard_grants": wildcards,
        "escalation_risks": escalation_risks,
        "ungranted_usage": ungranted_usage,
        "risk_score": risk_score,
        "findings": findings,
    }


def analyze(identities, usage):
    """Analyze every identity; results sorted by descending risk score."""
    results = [
        analyze_identity(identity, usage.get(identity["name"], {}))
        for identity in identities
    ]
    results.sort(key=lambda r: (-r["risk_score"], r["identity"]))
    return results
