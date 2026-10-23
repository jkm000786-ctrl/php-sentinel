from dataclasses import dataclass


@dataclass(frozen=True)
class PHPAdvisory:
    cve: str
    description: str


OCT_2026_CRITICAL = (
    PHPAdvisory(
        cve="CVE-2026-109618",
        description="Critical PHP request-processing memory-corruption issue.",
    ),
    PHPAdvisory(
        cve="CVE-2026-109619",
        description="Critical PHP stale request-state issue.",
    ),
)

FIXED_UPSTREAM = {
    (8, 5): (8, 5, 12),
    (8, 4): (8, 4, 27),
    (8, 3): (8, 3, 36),
    (8, 2): (8, 2, 35),
}
