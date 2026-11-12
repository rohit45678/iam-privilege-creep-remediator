"""Tests for the IAM Privilege-Creep Remediator.

Runnable two ways:
    python tests/run_tests.py     (plain-assert runner, no dependencies)
    python -m pytest tests/       (if pytest is installed)
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from iam_remediator import analyzer, generator, loaders, report

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
POLICIES = os.path.join(ROOT, "sample_data", "policies.json")
USAGE = os.path.join(ROOT, "sample_data", "usage_log.csv")


def _load():
    identities = loaders.load_policies(POLICIES)
    usage = loaders.load_usage(USAGE)
    by_name = {i["name"]: i for i in identities}
    return identities, usage, by_name


def _analyze(name):
    identities, usage, by_name = _load()
    return analyzer.analyze_identity(by_name[name], usage.get(name, {}))


def test_loaders_load_all_identities():
    identities, usage, _ = _load()
    assert [i["name"] for i in identities] == [
        "data-analyst",
        "ci-deployer",
        "legacy-admin",
        "gcp-etl-service",
        "dormant-backup",
    ]
    # Only successful calls count as usage: the Denied s3:DeleteObject
    # attempt by data-analyst must not appear.
    assert set(usage["data-analyst"]) == {
        "s3:GetObject",
        "s3:ListBucket",
        "athena:StartQueryExecution",
        "athena:GetQueryResults",
    }
    assert "dormant-backup" not in usage


def test_pattern_matching():
    assert analyzer.pattern_matches("*", "iam:Anything")
    assert analyzer.pattern_matches("athena:*", "athena:StartQueryExecution")
    assert analyzer.pattern_matches("s3:Get*", "s3:GetObject")
    assert not analyzer.pattern_matches("athena:*", "s3:GetObject")
    assert analyzer.pattern_matches("s3:GetObject", "s3:GetObject")
    assert not analyzer.pattern_matches("s3:GetObject", "s3:PutObject")


def test_data_analyst_unused_and_wildcard():
    result = _analyze("data-analyst")
    assert result["unused_permissions"] == [
        "ec2:DescribeInstances",
        "rds:DescribeDBInstances",
        "s3:DeleteObject",
        "s3:PutObject",
    ]
    assert result["wildcard_grants"] == ["athena:*"]
    assert result["escalation_risks"] == []
    assert result["risk_score"] == 7


def test_ci_deployer_escalation_flagged():
    result = _analyze("ci-deployer")
    assert result["unused_permissions"] == ["iam:PassRole"]
    assert result["wildcard_grants"] == ["ec2:*", "lambda:*"]
    assert len(result["escalation_risks"]) == 1
    risk = result["escalation_risks"][0]
    assert risk["action"] == "iam:PassRole"
    assert risk["used"] is False
    assert risk["severity"] == "critical"
    assert result["risk_score"] == 17


def test_legacy_admin_full_admin_is_highest_risk():
    result = _analyze("legacy-admin")
    assert result["unused_permissions"] == []
    assert result["wildcard_grants"] == ["*"]
    assert any(f["type"] == "full_admin" for f in result["findings"])
    # Every escalation action is covered by the "*" grant.
    assert len(result["escalation_risks"]) == len(analyzer.ESCALATION_ACTIONS)
    assert result["risk_score"] == 183

    identities, usage, _ = _load()
    analyses = analyzer.analyze(identities, usage)
    assert analyses[0]["identity"] == "legacy-admin"


def test_gcp_service_account():
    result = _analyze("gcp-etl-service")
    assert result["unused_permissions"] == [
        "bigquery.datasets.get",
        "iam.serviceAccounts.actAs",
        "storage.objects.create",
        "storage.objects.delete",
    ]
    assert [r["action"] for r in result["escalation_risks"]] == [
        "iam.serviceAccounts.actAs"
    ]
    assert result["risk_score"] == 14


def test_dormant_identity():
    result = _analyze("dormant-backup")
    assert result["used_actions"] == []
    assert result["unused_permissions"] == [
        "rds:CreateDBSnapshot",
        "s3:ListBucket",
        "s3:PutObject",
    ]
    assert any(f["type"] == "dormant_identity" for f in result["findings"])


def test_generated_policy_contains_only_used_actions():
    identities, usage, by_name = _load()
    for name in ("data-analyst", "ci-deployer", "legacy-admin", "gcp-etl-service"):
        gen = generator.generate_policy(by_name[name], usage.get(name, {}))
        actions = generator.policy_actions(gen)
        assert actions == sorted(usage[name]), (name, actions)
        assert all("*" not in a for a in actions), name


def test_generated_policy_scopes_resources():
    _, usage, by_name = _load()
    gen = generator.generate_policy(by_name["data-analyst"], usage["data-analyst"])
    get_object_resources = [
        s["Resource"] for s in gen["policy"]["Statement"] if "s3:GetObject" in s["Action"]
    ]
    # s3:GetObject was used on concrete bucket objects, never on "*".
    assert get_object_resources
    assert all(r.startswith("arn:aws:s3:::") for r in get_object_resources)
    # The escalation permission must not survive remediation.
    deployer = generator.generate_policy(by_name["ci-deployer"], usage["ci-deployer"])
    assert "iam:PassRole" not in generator.policy_actions(deployer)


def test_generated_policy_for_dormant_identity_is_empty():
    _, usage, by_name = _load()
    gen = generator.generate_policy(by_name["dormant-backup"], usage.get("dormant-backup", {}))
    assert gen["policy"]["Statement"] == []
    assert gen["notes"]


def test_report_totals():
    identities, usage, _ = _load()
    analyses = analyzer.analyze(identities, usage)
    generated = [
        generator.generate_policy(i, usage.get(i["name"], {})) for i in identities
    ]
    full = report.build_report(analyses, generated)
    assert full["summary"]["identities_analyzed"] == 5
    assert full["summary"]["unused_permissions_total"] == 12
    assert full["summary"]["escalation_capable_grants_total"] == 15
    assert full["summary"]["highest_risk_identity"] == "legacy-admin"
    summary_text = report.render_summary(full)
    assert "legacy-admin" in summary_text
