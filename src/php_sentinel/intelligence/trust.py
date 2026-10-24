from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.exceptions import (
    InvalidSignature,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from php_sentinel.intelligence.delegation import (
    resolve_authorized_predecessor_evidence,
)
from php_sentinel.intelligence.repository import (
    default_policy,
    load_policy,
    policy_sha256,
)
from php_sentinel.models.intelligence_policy import (
    IntelligencePolicy,
)
from php_sentinel.models.intelligence_trust import (
    IntelligenceManifest,
    IntelligenceTrustDecision,
    IntelligenceTrustState,
    TrustStore,
)

SUPPORTED_MANIFEST_VERSIONS = frozenset({1, 2, 3})

MANIFEST_SIGNATURE_DOMAIN_V3 = b"PHP-SENTINEL-INTELLIGENCE-MANIFEST-V3\x00"

ED25519_PRIVATE_KEY_BYTES = 32
ED25519_PUBLIC_KEY_BYTES = 32
ED25519_SIGNATURE_BYTES = 64


def manifest_signing_payload(
    manifest: IntelligenceManifest,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "manifest_version": (manifest.manifest_version),
        "policy_id": manifest.policy_id,
        "schema_version": (manifest.schema_version),
        "policy_sha256": (manifest.policy_sha256),
        "issued_at": (manifest.issued_at.isoformat()),
        "signer_id": manifest.signer_id,
        "algorithm": manifest.algorithm,
    }

    if manifest.manifest_version >= 2:
        payload["generation"] = manifest.generation
        payload["expires_at"] = manifest.expires_at.isoformat() if manifest.expires_at else None

    return payload


def manifest_signing_bytes(
    manifest: IntelligenceManifest,
) -> bytes:
    canonical = json.dumps(
        manifest_signing_payload(manifest),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    if manifest.manifest_version >= 3:
        return MANIFEST_SIGNATURE_DOMAIN_V3 + canonical

    # v1/v2 compatibility path.
    return canonical


def parse_manifest_bytes(
    payload: bytes,
) -> IntelligenceManifest:
    data = json.loads(payload.decode("utf-8"))

    manifest = IntelligenceManifest.model_validate(data)

    if manifest.manifest_version not in SUPPORTED_MANIFEST_VERSIONS:
        supported = ", ".join(str(item) for item in sorted(SUPPORTED_MANIFEST_VERSIONS))

        raise ValueError(
            "Unsupported intelligence manifest "
            f"version={manifest.manifest_version}. "
            f"Supported versions: {supported}."
        )

    return manifest


def load_manifest(
    path: Path | str,
) -> IntelligenceManifest:
    return parse_manifest_bytes(Path(path).read_bytes())


def load_trust_store(
    path: Path | str,
) -> TrustStore:
    data = json.loads(Path(path).read_text(encoding="utf-8"))

    return TrustStore.model_validate(data)


def bundled_policy_trust(
    policy: IntelligencePolicy,
) -> IntelligenceTrustDecision:
    return IntelligenceTrustDecision(
        state=(IntelligenceTrustState.BUNDLED_TRUSTED),
        trusted=True,
        policy_id=policy.policy_id,
        policy_sha256=policy_sha256(policy),
        signer_id="php-sentinel-package",
        algorithm="package-bound",
        rationale=[
            (
                "The intelligence policy is the "
                "validated policy bundled with this "
                "PHP Sentinel installation."
            ),
            (
                "Bundled trust establishes "
                "package-local trust, not independent "
                "PHP upstream publisher "
                "authentication."
            ),
        ],
    )


def unsigned_policy_trust(
    policy: IntelligencePolicy,
) -> IntelligenceTrustDecision:
    return IntelligenceTrustDecision(
        state=IntelligenceTrustState.UNSIGNED,
        trusted=False,
        policy_id=policy.policy_id,
        policy_sha256=policy_sha256(policy),
        rationale=[
            (
                "The policy was supplied without a "
                "verified trusted intelligence "
                "activation capability."
            )
        ],
    )


def resolve_policy_trust(
    policy: IntelligencePolicy,
    supplied: (IntelligenceTrustDecision | None) = None,
) -> IntelligenceTrustDecision:
    """Resolve trust for callers outside the verified activation path."""

    actual_digest = policy_sha256(policy)

    bundled = default_policy()

    if policy.policy_id == bundled.policy_id and actual_digest == policy_sha256(bundled):
        return bundled_policy_trust(policy)

    if supplied is not None:
        return IntelligenceTrustDecision(
            state=(IntelligenceTrustState.METADATA_MISMATCH),
            trusted=False,
            policy_id=policy.policy_id,
            policy_sha256=actual_digest,
            signer_id=supplied.signer_id,
            algorithm=supplied.algorithm,
            rationale=[
                (
                    "Caller-supplied trust decisions "
                    "are not accepted as verification "
                    "authority. External trust must "
                    "originate from the activation "
                    "boundary."
                )
            ],
        )

    return unsigned_policy_trust(policy)


def verify_manifest(
    policy: IntelligencePolicy,
    manifest: IntelligenceManifest,
    trust_store: TrustStore,
    *,
    now: datetime | None = None,
) -> IntelligenceTrustDecision:
    digest = policy_sha256(policy)

    if manifest.algorithm != "ed25519":
        return IntelligenceTrustDecision(
            state=(IntelligenceTrustState.UNSUPPORTED_ALGORITHM),
            trusted=False,
            policy_id=policy.policy_id,
            policy_sha256=digest,
            signer_id=manifest.signer_id,
            algorithm=manifest.algorithm,
            rationale=[("The manifest signature algorithm is not supported.")],
        )

    if manifest.policy_id != policy.policy_id or manifest.schema_version != policy.schema_version:
        return IntelligenceTrustDecision(
            state=(IntelligenceTrustState.METADATA_MISMATCH),
            trusted=False,
            policy_id=policy.policy_id,
            policy_sha256=digest,
            signer_id=manifest.signer_id,
            algorithm=manifest.algorithm,
            rationale=[("Manifest policy metadata does not match the validated policy.")],
        )

    if manifest.policy_sha256 != digest:
        return IntelligenceTrustDecision(
            state=(IntelligenceTrustState.DIGEST_MISMATCH),
            trusted=False,
            policy_id=policy.policy_id,
            policy_sha256=digest,
            signer_id=manifest.signer_id,
            algorithm=manifest.algorithm,
            rationale=[("Manifest policy SHA-256 does not match the validated policy content.")],
        )

    signer = next(
        (
            item
            for item in trust_store.signers
            if (item.signer_id == manifest.signer_id and item.enabled)
        ),
        None,
    )

    if signer is None:
        return IntelligenceTrustDecision(
            state=(IntelligenceTrustState.UNKNOWN_SIGNER),
            trusted=False,
            policy_id=policy.policy_id,
            policy_sha256=digest,
            signer_id=manifest.signer_id,
            algorithm=manifest.algorithm,
            rationale=[("Manifest signer is not present as an enabled trusted signer.")],
        )

    if signer.algorithm != manifest.algorithm or signer.algorithm != "ed25519":
        return IntelligenceTrustDecision(
            state=(IntelligenceTrustState.UNSUPPORTED_ALGORITHM),
            trusted=False,
            policy_id=policy.policy_id,
            policy_sha256=digest,
            signer_id=manifest.signer_id,
            algorithm=manifest.algorithm,
            rationale=[("Signer algorithm does not match a supported manifest algorithm.")],
        )

    try:
        public_key_bytes = base64.b64decode(
            signer.public_key_b64,
            validate=True,
        )

        signature = base64.b64decode(
            manifest.signature_b64,
            validate=True,
        )

        if len(public_key_bytes) != ED25519_PUBLIC_KEY_BYTES:
            raise ValueError("Invalid Ed25519 public-key length.")

        if len(signature) != ED25519_SIGNATURE_BYTES:
            raise ValueError("Invalid Ed25519 signature length.")

        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

        public_key.verify(
            signature,
            manifest_signing_bytes(manifest),
        )

    except (
        ValueError,
        InvalidSignature,
    ):
        return IntelligenceTrustDecision(
            state=(IntelligenceTrustState.INVALID_SIGNATURE),
            trusted=False,
            policy_id=policy.policy_id,
            policy_sha256=digest,
            signer_id=manifest.signer_id,
            algorithm=manifest.algorithm,
            rationale=[("Ed25519 signature verification failed.")],
        )

    rationale = [
        ("The policy digest matches the manifest."),
        ("The Ed25519 signature was verified against an enabled trusted signer."),
    ]

    if manifest.manifest_version >= 3:
        rationale.append(
            "The signature is domain-separated for PHP Sentinel intelligence manifest v3."
        )
    else:
        rationale.append("This is a legacy pre-domain-separation manifest signature.")

    delegation_evidence = resolve_authorized_predecessor_evidence(
        trust_store=trust_store,
        successor_signer_id=(manifest.signer_id),
        successor_public_key_b64=(signer.public_key_b64),
        context="intelligence",
        now=now,
    )

    authorized_predecessors = sorted(delegation_evidence)

    predecessor_minimum_generations = {
        predecessor_id: (evidence.minimum_successor_generation)
        for predecessor_id, evidence in delegation_evidence.items()
    }

    if signer.authorized_predecessors:
        rationale.append(
            "Legacy authorized_predecessors metadata is present "
            "but is not accepted as rotation authority."
        )

    if authorized_predecessors:
        rationale.append(
            "Signer rotation authorization was established by valid predecessor-signed delegation."
        )

    return IntelligenceTrustDecision(
        state=IntelligenceTrustState.TRUSTED,
        trusted=True,
        policy_id=policy.policy_id,
        policy_sha256=digest,
        signer_id=manifest.signer_id,
        algorithm=manifest.algorithm,
        authorized_predecessor_signer_ids=(authorized_predecessors),
        authorized_predecessor_minimum_generations=(predecessor_minimum_generations),
        authorized_predecessor_delegations=(delegation_evidence),
        rationale=rationale,
    )


def load_verified_external_bundle(
    *,
    policy_path: Path | str,
    manifest_path: Path | str,
    trust_store_path: Path | str,
) -> tuple[
    IntelligencePolicy,
    IntelligenceManifest,
    IntelligenceTrustDecision,
]:
    policy = load_policy(policy_path)

    manifest = load_manifest(manifest_path)

    trust_store = load_trust_store(trust_store_path)

    decision = verify_manifest(
        policy,
        manifest,
        trust_store,
    )

    if not decision.trusted:
        raise ValueError(
            f"External intelligence policy trust verification failed: {decision.state.value}."
        )

    return (
        policy,
        manifest,
        decision,
    )


def load_verified_external_policy(
    *,
    policy_path: Path | str,
    manifest_path: Path | str,
    trust_store_path: Path | str,
) -> tuple[
    IntelligencePolicy,
    IntelligenceTrustDecision,
]:
    (
        policy,
        _,
        decision,
    ) = load_verified_external_bundle(
        policy_path=policy_path,
        manifest_path=manifest_path,
        trust_store_path=trust_store_path,
    )

    return policy, decision


def create_signed_manifest(
    *,
    policy: IntelligencePolicy,
    signer_id: str,
    private_key_b64: str,
    issued_at: datetime | None = None,
    generation: int = 1,
    expires_at: datetime | None = None,
    validity_days: int = 30,
    manifest_version: int = 3,
) -> IntelligenceManifest:
    private_bytes = base64.b64decode(
        private_key_b64,
        validate=True,
    )

    if len(private_bytes) != ED25519_PRIVATE_KEY_BYTES:
        raise ValueError("Ed25519 private key must decode to exactly 32 bytes.")

    private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)

    issued = issued_at or datetime.now(UTC)

    if manifest_version >= 2:
        expiry = expires_at or (issued + timedelta(days=validity_days))
        manifest_generation = generation
    else:
        expiry = None
        manifest_generation = None

    placeholder = base64.b64encode(b"\x00" * ED25519_SIGNATURE_BYTES).decode("ascii")

    manifest = IntelligenceManifest(
        manifest_version=manifest_version,
        policy_id=policy.policy_id,
        schema_version=(policy.schema_version),
        policy_sha256=policy_sha256(policy),
        generation=manifest_generation,
        issued_at=issued,
        expires_at=expiry,
        signer_id=signer_id,
        algorithm="ed25519",
        signature_b64=placeholder,
    )

    signature = private_key.sign(manifest_signing_bytes(manifest))

    return manifest.model_copy(
        update={"signature_b64": (base64.b64encode(signature).decode("ascii"))}
    )
