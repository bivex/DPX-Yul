"""Yul Idiomatic, EVM Memory & Storage Architecture rules."""

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


class YulObjectRuntimeHierarchyRule(BaseRule):
    """Detects nested Yul objects declaring constructor init code and deployed runtime object."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for obj in model.all_objects:
            if obj.sub_objects or "_deployed" in obj.name.lower() or "runtime" in obj.name.lower():
                evidences = [
                    Evidence(
                        rule_code="YUL_OBJECT_RUNTIME_HIERARCHY",
                        description=f"Yul object '{obj.name}' defines multi-tier deployment and runtime hierarchy",
                        weight=0.95,
                        location=obj.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.YUL_OBJECT_RUNTIME_HIERARCHY,
                        pattern_category=PatternCategory.YUL_IDIOMATIC_EVM,
                        target_name=obj.name,
                        target_kind="object",
                        confidence=Confidence(score=0.95, evidences=evidences),
                        primary_location=obj.location,
                        evidences=evidences,
                    )
                )
        return detections


class FreeMemoryPointerManagementRule(BaseRule):
    """Detects standard EVM memory allocation loading and updating 0x40 pointer."""

    MEM_PATTERN = re.compile(r"\bmload\s*\(\s*0x40\s*\)")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if fn.has_mload_40 or self.MEM_PATTERN.search(fn.body):
                evidences = [
                    Evidence(
                        rule_code="YUL_FREE_MEMORY_POINTER",
                        description=f"Function '{fn.name}' implements 0x40 free memory pointer management (mload(0x40))",
                        weight=0.95,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.FREE_MEMORY_POINTER_MANAGEMENT,
                        pattern_category=PatternCategory.YUL_IDIOMATIC_EVM,
                        target_name=fn.name,
                        target_kind="function",
                        confidence=Confidence(score=0.95, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class TransientStorageEip1153Rule(BaseRule):
    """Detects transaction-scoped temporary storage using tstore and tload opcodes (EIP-1153)."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if fn.has_tstore or fn.has_tload or "tstore(" in fn.body or "tload(" in fn.body:
                evidences = [
                    Evidence(
                        rule_code="YUL_TRANSIENT_STORAGE_EIP1153",
                        description=f"Function '{fn.name}' utilizes EIP-1153 transient storage opcodes (tstore / tload)",
                        weight=0.98,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.TRANSIENT_STORAGE_EIP1153,
                        pattern_category=PatternCategory.YUL_IDIOMATIC_EVM,
                        target_name=fn.name,
                        target_kind="function",
                        confidence=Confidence(score=0.98, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class CustomFourbyteSelectorDispatcherRule(BaseRule):
    """Detects direct calldata extraction of function selector (shr(224, calldataload(0))) with switch routing."""

    SELECTOR_PATTERN = re.compile(r"shr\s*\(\s*224\s*,\s*calldataload\s*\(\s*0\s*\)\s*\)")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if self.SELECTOR_PATTERN.search(fn.body) or ("calldataload(0)" in fn.body and "switch" in fn.body):
                evidences = [
                    Evidence(
                        rule_code="YUL_SELECTOR_DISPATCHER",
                        description=f"Function '{fn.name}' implements a custom 4-byte selector switch-case dispatcher",
                        weight=0.95,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.CUSTOM_FOURBYTE_SELECTOR_DISPATCHER,
                        pattern_category=PatternCategory.YUL_IDIOMATIC_EVM,
                        target_name=fn.name,
                        target_kind="function",
                        confidence=Confidence(score=0.95, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class StorageSlotBitfieldPackingRule(BaseRule):
    """Detects bitwise shift and mask operations packing variables into single 32-byte storage slots."""

    PACKING_PATTERN = re.compile(r"\b(shl|shr)\b[\s\S]*?\b(or|and)\b[\s\S]*?\bsstore\s*\(")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if self.PACKING_PATTERN.search(fn.body) or (fn.has_sstore and ("shl(" in fn.body or "shr(" in fn.body) and "or(" in fn.body):
                evidences = [
                    Evidence(
                        rule_code="YUL_BITFIELD_SLOT_PACKING",
                        description=f"Function '{fn.name}' packs multiple sub-word variables into a storage slot using bitwise shifts and masks",
                        weight=0.92,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.STORAGE_SLOT_BITFIELD_PACKING,
                        pattern_category=PatternCategory.YUL_IDIOMATIC_EVM,
                        target_name=fn.name,
                        target_kind="function",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class CustomErrorMemoryRevertRule(BaseRule):
    """Detects low-level custom error encoding in scratch space (mstore(0x00, selector), revert(0x1c, 0x24))."""

    REVERT_PATTERN = re.compile(r"revert\s*\(\s*(0x1c|0x00|\w+)\s*,\s*(0x24|0x04|4|36|\w+)\s*\)")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if fn.has_revert and (self.REVERT_PATTERN.search(fn.body) or "revert(" in fn.body):
                evidences = [
                    Evidence(
                        rule_code="YUL_CUSTOM_ERROR_REVERT",
                        description=f"Function '{fn.name}' encodes low-level custom error selectors and reverts with exact byte size",
                        weight=0.92,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.CUSTOM_ERROR_MEMORY_REVERT,
                        pattern_category=PatternCategory.YUL_IDIOMATIC_EVM,
                        target_name=fn.name,
                        target_kind="function",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections
