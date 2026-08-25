"""Base rule protocol for Yul & EVM Assembly static analysis rules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pattern_detector.domain.code_model import CodeModel
from pattern_detector.domain.detection import Detection


class BaseRule(ABC):
    """Abstract base class for all Yul architectural detection rules."""

    @abstractmethod
    def evaluate(self, model: CodeModel) -> list[Detection]:
        """Evaluate the rule against the parsed Yul CodeModel."""
        pass
