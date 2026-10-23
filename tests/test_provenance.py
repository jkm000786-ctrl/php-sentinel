from php_sentinel.evidence.provenance import (
    POLICY_VERSION,
    build_provenance,
    sha256_payload,
)


def test_canonical_hash_is_deterministic():
    first = sha256_payload(
        {
            "b": 2,
            "a": 1,
        }
    )

    second = sha256_payload(
        {
            "a": 1,
            "b": 2,
        }
    )

    assert first == second
    assert len(first) == 64


def test_content_change_changes_hash():
    first = sha256_payload(
        {
            "version": "8.5.11",
        }
    )

    second = sha256_payload(
        {
            "version": "8.5.12",
        }
    )

    assert first != second


def test_provenance_contains_report_identity():
    provenance = build_provenance(
        canonical_payload={
            "target": "http://127.0.0.1/",
            "version": "8.5.11",
        },
        target_identity_payload={
            "target": "http://127.0.0.1/",
        },
    )

    assert provenance.report_id
    assert provenance.tool_name == "PHP Sentinel"
    assert provenance.policy_version == POLICY_VERSION
    assert len(provenance.canonical_sha256) == 64
    assert len(provenance.target_identity_sha256) == 64


def test_volatile_timestamps_do_not_change_canonical_hash():
    first = sha256_payload(
        {
            "target": "http://127.0.0.1/",
            "evidence": [
                {
                    "kind": "http_header",
                    "value": "PHP/8.5.12",
                    "observed_at": "2026-10-23T16:00:00Z",
                }
            ],
            "generated_at": "2026-10-23T16:00:01Z",
        }
    )

    second = sha256_payload(
        {
            "target": "http://127.0.0.1/",
            "evidence": [
                {
                    "kind": "http_header",
                    "value": "PHP/8.5.12",
                    "observed_at": "2026-10-23T17:45:00Z",
                }
            ],
            "generated_at": "2026-10-23T17:45:01Z",
        }
    )

    assert first == second


def test_material_evidence_change_still_changes_hash():
    first = sha256_payload(
        {
            "php_version": "8.5.11",
            "observed_at": "2026-10-23T16:00:00Z",
        }
    )

    second = sha256_payload(
        {
            "php_version": "8.5.12",
            "observed_at": "2026-10-23T17:00:00Z",
        }
    )

    assert first != second


def test_provenance_contains_intelligence_identity():
    from php_sentinel.intelligence.repository import (
        default_policy,
        policy_sha256,
    )

    policy = default_policy()

    provenance = build_provenance(
        canonical_payload={
            "target": "http://127.0.0.1/",
        },
        target_identity_payload={
            "target": "http://127.0.0.1/",
        },
        intelligence_policy=policy,
    )

    assert provenance.intelligence_policy_id == policy.policy_id

    assert provenance.intelligence_schema_version == policy.schema_version

    assert provenance.intelligence_sha256 == policy_sha256(policy)

    assert provenance.intelligence_sha256 is not None

    assert len(provenance.intelligence_sha256) == 64


def test_legacy_provenance_without_intelligence_fields_loads():
    from php_sentinel.models.provenance import (
        EvidenceProvenance,
    )

    provenance = EvidenceProvenance(
        report_id="legacy-report",
        tool_name="PHP Sentinel",
        tool_version="0.1.0",
        policy_version="2026-10-23.1",
        canonical_sha256="a" * 64,
        target_identity_sha256="b" * 64,
    )

    assert provenance.intelligence_policy_id is None

    assert provenance.intelligence_sha256 is None


def test_bundled_policy_is_marked_package_trusted():
    provenance = build_provenance(
        canonical_payload={
            "target": "bundled",
        },
        target_identity_payload={
            "target": "bundled",
        },
    )

    assert provenance.intelligence_trust_state == "bundled_trusted"

    assert provenance.intelligence_signer_id == "php-sentinel-package"


def test_custom_unsigned_policy_is_not_marked_trusted():
    from php_sentinel.intelligence.repository import (
        default_policy,
    )

    policy = default_policy().model_copy(deep=True)

    policy.fixed_versions["8.5"] = "8.5.13"

    provenance = build_provenance(
        canonical_payload={
            "target": "custom",
        },
        target_identity_payload={
            "target": "custom",
        },
        intelligence_policy=policy,
    )

    assert provenance.intelligence_trust_state == "unsigned"

    assert provenance.intelligence_signer_id is None
