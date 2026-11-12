"""Least-privilege policy generation.

The generated replacement policy for an identity contains exactly the
actions observed in successful usage (and covered by an existing grant),
grouped into statements by the resource they were used on. Wildcards from
the original grants never survive: a used action that was granted via a
wildcard pattern is emitted as the concrete action that was exercised.
"""

from __future__ import annotations

from .analyzer import is_granted


def generate_policy(identity, usage_for_identity):
    """Build a tightened policy document for one identity.

    Returns ``{"identity": ..., "cloud": ..., "policy": {...},
    "notes": [...]}``. Identities with no observed usage get an empty
    statement list plus a note recommending the identity be disabled or
    its grants revoked pending owner review.
    """
    by_resource = {}
    for action in sorted(usage_for_identity):
        if not is_granted(identity, action):
            # Successful usage without a grant is reported by the analyzer;
            # it must not silently become a grant here.
            continue
        record = usage_for_identity[action]
        resources = sorted(r for r in record["resources"] if r and r != "*")
        targets = resources if resources else ["*"]
        for resource in targets:
            by_resource.setdefault(resource, set()).add(action)

    statements = []
    for resource in sorted(by_resource):
        statements.append(
            {
                "Effect": "Allow",
                "Action": sorted(by_resource[resource]),
                "Resource": resource,
            }
        )

    notes = []
    if not statements:
        notes.append(
            "No usage observed in the analysis window; recommend disabling "
            "this identity or revoking its grants pending owner review."
        )

    return {
        "identity": identity["name"],
        "cloud": identity["cloud"],
        "policy": {"Version": "2012-10-17", "Statement": statements},
        "notes": notes,
    }


def policy_actions(generated):
    """Flat sorted list of every action in a generated policy."""
    actions = set()
    for statement in generated["policy"]["Statement"]:
        actions.update(statement["Action"])
    return sorted(actions)
