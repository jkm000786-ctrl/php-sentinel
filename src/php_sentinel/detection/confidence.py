from __future__ import annotations


def calculate_php_confidence(
    *,
    php_detected: bool,
    version_known: bool,
    x_powered_by_present: bool,
    body_php_marker: bool,
) -> float:
    score = 0.0

    if php_detected:
        score += 0.35
    if x_powered_by_present:
        score += 0.30
    if version_known:
        score += 0.25
    if body_php_marker:
        score += 0.10

    return min(round(score, 2), 1.0)
