# IAM Privilege-Creep Remediator
Multi-cloud automation that analyzes IAM usage, identifies privilege creep (granted-but-unused permissions), and generates least-privilege replacement policies to reduce the cloud attack surface.
**Tech stack:** Python, AWS, Azure, GCP, IAM, Cloud Security
**Highlights:** cross-cloud permission usage analysis; unused-permission detection; automated least-privilege policy generation.

## Implementation

A self-contained Python 3 implementation (standard library only, no
dependencies) of the remediator pipeline. It compares the permissions each
identity is *granted* with the permissions it actually *used* over a 90-day
window, scores the resulting risk, and emits a tightened replacement policy
per identity containing only exercised permissions, scoped to the resources
they were exercised on.

### Features

- **Usage analysis** — granted-vs-used diff per identity; denied attempts in
  the log are ignored, so an attempted-but-blocked call never counts as usage.
- **Privilege-creep detection** — unused concrete permissions, wildcard grants
  (`ec2:*`, `athena:*`, …), dormant identities with grants but zero usage,
  and successful usage not covered by any grant.
- **Escalation screening** — granted actions checked against a built-in set of
  privilege-escalation-capable actions (AWS `iam:PassRole`,
  `iam:CreatePolicyVersion`, `iam:AttachUserPolicy`, `sts:AssumeRole`, …;
  GCP `iam.serviceAccounts.actAs`, `resourcemanager.projects.setIamPolicy`, …),
  whether granted directly or through a wildcard.
- **Risk scoring** — deterministic, documented scoring (full-admin grant +50,
  unused escalation action +10, wildcard grant +3, unused permission +1, …)
  so identities can be ranked for remediation order.
- **Least-privilege generation** — one replacement policy per identity with
  exactly the used actions, grouped by resource; wildcards never survive,
  and identities with no usage get an empty policy with a disable/revoke
  recommendation.
- **Findings report** — machine-readable `findings.json` plus a printed
  human-readable summary.

### Architecture

```
main.py                  CLI entry point (--policies / --usage / --out)
iam_remediator/
  loaders.py             policy JSON + usage CSV loading
  analyzer.py            unused/wildcard/escalation analysis + risk scoring
  generator.py           least-privilege policy generation
  report.py              findings report assembly + summary rendering
sample_data/
  policies.json          5 sample identities (AWS users/roles, a GCP service
                         account, a full-admin user, a dormant role)
  usage_log.csv          90 days of sample access-log rows
tests/
  test_iam.py            test suite (pytest-compatible)
  run_tests.py           dependency-free test runner
```

### How to run

```bash
# Analyze the bundled sample data
python main.py --policies sample_data/policies.json \
               --usage sample_data/usage_log.csv \
               --out out/

# Run the tests
python tests/run_tests.py        # or: python -m pytest tests/
```

Outputs: `out/findings.json` and one tightened policy per identity in
`out/policies/<identity>.json`.

Input formats: policies are IAM-style JSON documents grouped by identity
(AWS-flavored action names and GCP permission names are both supported);
the usage log is a CSV with `timestamp,identity,action,resource,result`
columns, of which only `Success` rows count as usage.

### Sample output

```
IAM Privilege-Creep Remediation Report
============================================================
Identities analyzed : 5
Unused permissions  : 12
Escalation grants   : 15
Critical findings   : 16

legacy-admin (aws/user) - risk score 183
  granted patterns: 1 | used actions: 3 | unused permissions: 0
  [CRITICAL] Identity holds a full-administrator grant (Action: '*').
  [CRITICAL] iam:PassRole is granted via * and was never used in the window.
  ...

ci-deployer (aws/role) - risk score 17
  granted patterns: 4 | used actions: 6 | unused permissions: 1
  [CRITICAL] iam:PassRole is granted via iam:PassRole and was never used in the window.
  [MEDIUM] Wildcard grant 'ec2:*' covers more actions than observed usage.
  [MEDIUM] Wildcard grant 'lambda:*' covers more actions than observed usage.
  [MEDIUM] 1 granted permission(s) never used: iam:PassRole.

data-analyst (aws/user) - risk score 7
  granted patterns: 7 | used actions: 4 | unused permissions: 4
  [MEDIUM] Wildcard grant 'athena:*' covers more actions than observed usage.
  [MEDIUM] 4 granted permission(s) never used: ec2:DescribeInstances, rds:DescribeDBInstances, s3:DeleteObject, s3:PutObject.

dormant-backup (aws/role) - risk score 3
  granted patterns: 3 | used actions: 0 | unused permissions: 3
  [HIGH] Identity has grants but zero observed usage in the window.
```

The generated replacement policy for `data-analyst` (excerpt) — note how
`s3:GetObject` is scoped to the concrete objects it was actually used on,
and the `athena:*` wildcard collapses to the two exercised actions:

```json
{
  "Effect": "Allow",
  "Action": ["athena:GetQueryResults", "athena:StartQueryExecution"],
  "Resource": "*"
},
{
  "Effect": "Allow",
  "Action": ["s3:GetObject"],
  "Resource": "arn:aws:s3:::analytics-data/raw/customers.csv"
}
```
