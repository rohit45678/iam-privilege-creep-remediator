"""Loaders for IAM-style policy documents and permission usage logs.

Policy input format (JSON)::

    {
      "identities": [
        {
          "name": "data-analyst",
          "type": "user",                # user | role | service_account
          "cloud": "aws",                # aws | gcp | azure
          "policies": [
            {"name": "AnalystPolicy",
             "document": {"Version": "2012-10-17",
                          "Statement": [{"Effect": "Allow",
                                         "Action": ["s3:GetObject", ...],
                                         "Resource": "*"}]}}
          ]
        }
      ]
    }

Usage input format (CSV) with header::

    timestamp,identity,action,resource,result

Only rows whose ``result`` is ``Success`` count as observed usage; denied
attempts are ignored (an attempted-but-denied call is not a used grant).
"""

from __future__ import annotations

import csv
import json


def load_policies(path):
    """Load a policy JSON file.

    Returns a list of identity dicts::

        {"name": str, "type": str, "cloud": str,
         "granted": [{"action": <pattern>, "policy": <policy name>}, ...]}

    Only ``Allow`` statements contribute grants.
    """
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)

    identities = []
    for ident in data.get("identities", []):
        granted = []
        for policy in ident.get("policies", []):
            document = policy.get("document", {})
            for statement in document.get("Statement", []):
                if statement.get("Effect") != "Allow":
                    continue
                actions = statement.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                for action in actions:
                    granted.append({"action": action, "policy": policy.get("name", "")})
        identities.append(
            {
                "name": ident["name"],
                "type": ident.get("type", "user"),
                "cloud": ident.get("cloud", "aws"),
                "granted": granted,
            }
        )
    return identities


def load_usage(path):
    """Load a usage/access log CSV.

    Returns ``{identity_name: {action: {"count": int, "resources": set}}}``
    built from successful calls only.
    """
    usage = {}
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            if row.get("result", "Success") != "Success":
                continue
            per_identity = usage.setdefault(row["identity"], {})
            record = per_identity.setdefault(
                row["action"], {"count": 0, "resources": set()}
            )
            record["count"] += 1
            resource = (row.get("resource") or "").strip()
            if resource:
                record["resources"].add(resource)
    return usage
