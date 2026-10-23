import json

import pytest
from pydantic import ValidationError

from php_sentinel.intelligence.cve_database import (
    FIXED_UPSTREAM,
    OCT_2026_CRITICAL,
)
from php_sentinel.intelligence.repository import (
    cve_by_id,
    default_policy,
    fixed_version_for_branch,
    load_policy,
)


def test_default_policy_loads():
    policy = default_policy()

    assert policy.policy_id == "php-2026-10-critical"
    assert policy.schema_version == 1
    assert len(policy.cves) == 2


def test_fixed_thresholds_are_policy_backed():
    policy = default_policy()

    assert policy.fixed_versions == {
        "8.5": "8.5.12",
        "8.4": "8.4.27",
        "8.3": "8.3.36",
        "8.2": "8.2.35",
    }

    assert str(fixed_version_for_branch((8, 5))) == "8.5.12"


def test_legacy_database_facade_uses_policy():
    assert FIXED_UPSTREAM[(8, 5)] == (
        8,
        5,
        12,
    )

    assert {item.cve for item in OCT_2026_CRITICAL} == {
        "CVE-2026-109618",
        "CVE-2026-109619",
    }


def test_cve_specific_mitigation_is_policy_data():
    item = cve_by_id("CVE-2026-109619")

    assert item is not None

    text = " ".join(item.temporary_mitigations)

    assert "session.upload_progress.enabled=0" in text


def test_policy_rejects_branch_version_mismatch(
    tmp_path,
):
    policy = default_policy().model_dump(mode="json")

    policy["fixed_versions"]["8.5"] = "8.4.99"

    path = tmp_path / "bad-policy.json"
    path.write_text(
        json.dumps(policy),
        encoding="utf-8",
    )

    with pytest.raises(ValidationError):
        load_policy(path)


def test_policy_rejects_duplicate_cves(
    tmp_path,
):
    policy = default_policy().model_dump(mode="json")

    policy["cves"].append(dict(policy["cves"][0]))

    path = tmp_path / "duplicate.json"
    path.write_text(
        json.dumps(policy),
        encoding="utf-8",
    )

    with pytest.raises(ValidationError):
        load_policy(path)
