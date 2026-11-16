# src/sigmadft/adapters/atlas.py

from sigmadft.adapters.base import RuleAdapter
from sigmadft.reader.YAMLReader import YAMLReader
from sigmadft.rules.Rule import Rule


class AtlasAdapter(RuleAdapter):
    """Atlas rules (https://github.com/forensic-timeline/atlas).

    Atlas already uses the native SigmaDFT format (detection.keywords +
    high_level_event), so this adapter loads it unchanged.
    """

    name = "atlas"
    rules_subdir = "atlas/rules"

    def load(self, file_path: str) -> Rule:
        rule = YAMLReader(file_path).read()
        rule.source = self.name
        return rule
