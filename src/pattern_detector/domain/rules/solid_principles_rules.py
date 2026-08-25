"""SOLID principles and Yul code quality smell rules."""

from __future__ import annotations

import re
from pattern_detector.domain.code_model import CodeModel
from pattern_detector.domain.detection import Detection
from pattern_detector.domain.rules.base import BaseRule
from pattern_detector.domain.value_objects import (
    Confidence,
    Evidence,
    PatternCategory,
    PatternType,
)


class MonolithicYulObjectSrpRule(BaseRule):
    """Detects monolithic Yul objects or assembly blocks defining excessive functions (>= 15)."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for obj in model.all_objects:
            fn_cnt = len(obj.all_functions)
            if fn_cnt >= 15:
                evidences = [
                    Evidence(
                        rule_code="SRP_MONOLITHIC_YUL_OBJECT",
                        description=f"Yul object '{obj.name}' defines {fn_cnt} functions; decompose into modular helper libraries",
                        weight=0.88,
                        location=obj.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.MONOLITHIC_YUL_OBJECT_SRP,
                        pattern_category=PatternCategory.PRINCIPLE,
                        target_name=obj.name,
                        target_kind="object",
                        confidence=Confidence(score=0.88, evidences=evidences),
                        primary_location=obj.location,
                        evidences=evidences,
                    )
                )
        return detections


class FatMemoryStructIspRule(BaseRule):
    """Detects memory buffer accessing excessive word offsets (>= 10 distinct offsets)."""

    OFFSET_PATTERN = re.compile(r"(mstore|mload)\s*\(\s*add\s*\(\s*\w+\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*\)")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            offsets = set(self.OFFSET_PATTERN.findall(fn.body))
            if len(offsets) >= 10:
                evidences = [
                    Evidence(
                        rule_code="ISP_FAT_MEMORY_STRUCT",
                        description=f"Function '{fn.name}' accesses {len(offsets)} memory word offsets; decompose into cohesive sub-structs",
                        weight=0.88,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.FAT_MEMORY_STRUCT_ISP,
                        pattern_category=PatternCategory.PRINCIPLE,
                        target_name=fn.name,
                        target_kind="function",
                        confidence=Confidence(score=0.88, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class HardcodedStorageSlotOcpRule(BaseRule):
    """Detects hardcoding literal raw storage numbers (sstore(0, ...), sstore(1, ...)) without namespaces."""

    RAW_SLOT_PATTERN = re.compile(r"(sstore|sload)\s*\(\s*([0-9]|0x0[0-9])\s*,?")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            matches = self.RAW_SLOT_PATTERN.findall(fn.body)
            if matches and "keccak256" not in fn.body:
                evidences = [
                    Evidence(
                        rule_code="OCP_HARDCODED_STORAGE_SLOT",
                        description=f"Function '{fn.name}' uses raw literal storage slots ('{matches[0][1]}'); adopt ERC-7201 keccak namespace hashing",
                        weight=0.85,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.HARDCODED_STORAGE_SLOT_OCP,
                        pattern_category=PatternCategory.PRINCIPLE,
                        target_name=fn.name,
                        target_kind="function",
                        confidence=Confidence(score=0.85, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections
