from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel


def write_json_evidence(
    artifact: BaseModel,
    destination: str | Path,
) -> Path:
    path = Path(destination)

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        json.dumps(
            artifact.model_dump(mode="json"),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    return path
