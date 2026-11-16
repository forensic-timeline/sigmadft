# src/sigmadft/adapters/base.py

import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List

from sigmadft.rules.Rule import Rule

RULES_ROOT = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")


class RuleAdapter(ABC):
    """Base class: one adapter per rule source (folder under src/sigmadft/rules/)."""

    name: str = ""
    # Folder (relative to src/sigmadft/rules/) that holds this source's rules
    rules_subdir: str = ""

    @property
    def rules_dir(self) -> str:
        return os.path.join(RULES_ROOT, self.rules_subdir)

    def discover(self) -> List[str]:
        """Return sorted absolute paths of all *.yml / *.yaml rules of this source."""
        path = Path(self.rules_dir)
        if not path.exists():
            return []
        files = list(path.rglob("*.yml")) + list(path.rglob("*.yaml"))
        return sorted(str(f) for f in files)

    @abstractmethod
    def load(self, file_path: str) -> Rule:
        """Read one rule file and convert it into a SigmaDFT Rule."""
