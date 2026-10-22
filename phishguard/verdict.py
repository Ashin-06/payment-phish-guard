"""Common result type for every scanner."""
from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field

LEVELS = ((70, "dangerous"), (40, "suspicious"), (0, "safe"))


@dataclass
class Finding:
    weight: float  # positive = more risky, negative = reassuring
    message: str
    category: str = "general"


@dataclass
class Verdict:
    kind: str
    target: str
    findings: list[Finding] = field(default_factory=list)
    entities: dict = field(default_factory=dict)
    model_score: float | None = None
    advice: str = ""

    def add(self, weight: float, message: str, category: str = "general") -> None:
        self.findings.append(Finding(weight, message, category))

    @property
    def risk(self) -> int:
        """0-100. Rule weights saturate smoothly; a model score, when present, is blended in."""
        s = sum(f.weight for f in self.findings)
        rules = 100 * (1 - math.exp(-max(s, 0) / 4.0))
        if self.model_score is None:
            return round(rules)
        return round(max(rules, 0.7 * rules + 0.3 * 100 * self.model_score))

    @property
    def level(self) -> str:
        return next(name for cut, name in LEVELS if self.risk >= cut)

    def as_dict(self) -> dict:
        d = asdict(self)
        d.update(risk=self.risk, level=self.level)
        d["findings"] = sorted(d["findings"], key=lambda f: -f["weight"])
        return d
