from __future__ import annotations

from php_sentinel import __version__
from php_sentinel.models.operational_failure import (
    OperationalFailureEvidence,
)
from php_sentinel.models.transport import TransportEvidence


def build_operational_failure_evidence(
    *,
    target: str,
    transport: TransportEvidence,
) -> OperationalFailureEvidence:
    return OperationalFailureEvidence(
        tool_version=__version__,
        target=target,
        failure_reason=transport.execution.stop_reason,
        transport=transport,
    )
