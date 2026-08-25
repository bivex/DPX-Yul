"""Detection entity and DetectionReport domain representations for Yul."""

from __future__ import annotations

from dataclasses import dataclass, field
from pattern_detector.domain.pattern import PATTERN_CATALOG
from pattern_detector.domain.value_objects import (
    Confidence,
    ConfidenceLevel,
    Evidence,
    PatternCategory,
    PatternType,
    SourceLocation,
)


@dataclass
class Detection:
    """Represents a specific architectural pattern or security hazard instance in Yul code."""

    pattern_type: PatternType
    pattern_category: PatternCategory
    target_name: str
    target_kind: str  # "object", "function", "assembly", "memory", "storage"
    confidence: Confidence
    primary_location: SourceLocation | None = None
    related_locations: list[SourceLocation] = field(default_factory=list)
    evidences: list[Evidence] = field(default_factory=list)
    custom_summary: str | None = None

    @property
    def summary(self) -> str:
        if self.custom_summary:
            return self.custom_summary
        pdef = PATTERN_CATALOG.get(self.pattern_type)
        return pdef.description if pdef else f"Detected {self.pattern_type.value}"

    @property
    def level(self) -> ConfidenceLevel:
        return self.confidence.level

    def to_dict(self) -> dict:
        return {
            "pattern_type": self.pattern_type.value,
            "pattern_category": self.pattern_category.value,
            "target_name": self.target_name,
            "target_kind": self.target_kind,
            "confidence": {
                "score": self.confidence.score,
                "level": self.confidence.level.value,
                "percentage": self.confidence.percentage_str,
            },
            "primary_location": str(self.primary_location) if self.primary_location else None,
            "related_locations": [str(loc) for loc in self.related_locations],
            "summary": self.summary,
            "evidences": [
                {
                    "rule_code": ev.rule_code,
                    "description": ev.description,
                    "weight": ev.weight,
                    "location": str(ev.location) if ev.location else None,
                }
                for ev in self.evidences
            ],
        }


@dataclass
class DetectionReport:
    """Aggregated scan findings for an entire Yul project."""

    project_path: str
    scanned_files_count: int
    detections: list[Detection] = field(default_factory=list)
    elapsed_seconds: float = 0.0

    @property
    def total_detections_count(self) -> int:
        return len(self.detections)

    @property
    def summary_by_category(self) -> dict[str, int]:
        summary: dict[str, int] = {cat.value: 0 for cat in PatternCategory}
        for d in self.detections:
            summary[d.pattern_category.value] = summary.get(d.pattern_category.value, 0) + 1
        return summary

    def to_dict(self) -> dict:
        return {
            "project_path": self.project_path,
            "scanned_files_count": self.scanned_files_count,
            "total_detections_count": self.total_detections_count,
            "elapsed_seconds": self.elapsed_seconds,
            "summary_by_category": self.summary_by_category,
            "detections": [d.to_dict() for d in self.detections],
        }
