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
