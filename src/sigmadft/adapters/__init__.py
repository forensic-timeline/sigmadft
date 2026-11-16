# src/sigmadft/adapters/__init__.py
"""Rule adapters: convert rules from different sources into SigmaDFT Rule objects."""

from typing import Dict, Type

from sigmadft.adapters.base import RuleAdapter
from sigmadft.adapters.atlas import AtlasAdapter
from sigmadft.adapters.sigma import SigmaAdapter

ADAPTERS: Dict[str, Type[RuleAdapter]] = {
    AtlasAdapter.name: AtlasAdapter,
    SigmaAdapter.name: SigmaAdapter,
}


def get_adapter(name: str) -> RuleAdapter:
    try:
        return ADAPTERS[name]()
    except KeyError:
        raise ValueError(
            f"Unknown rule source '{name}'. Available: {', '.join(ADAPTERS)}"
        )
