"""Yul & EVM Assembly Security Hazards & Vulnerability detection rules."""

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


class UnprotectedDelegatecallHazardRule(BaseRule):
    """Detects delegatecall targeting calldata-supplied or unverified addresses."""

    CALLDATA_TARGET_PATTERN = re.compile(r"delegatecall\s*\(\s*gas\(\)\s*,\s*(calldataload\([^)]+\)|\w+)\s*,")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if fn.has_delegatecall:
                # Check if delegatecall is executed without caller check / authorization
                has_auth = any(kw in fn.body for kw in ("caller()", "sload(", "assert", "require", "check_owner"))
                if not has_auth or "calldataload(" in fn.body:
                    if "proxy" not in fn.name.lower() or not has_auth:
                        evidences = [
                            Evidence(
                                rule_code="HAZARD_UNPROTECTED_DELEGATECALL",
                                description=f"Function '{fn.name}' executes delegatecall without verifying implementation address or caller authorization",
                                weight=0.95,
                                location=fn.location,
                            )
                        ]
                        detections.append(
                            Detection(
                                pattern_type=PatternType.UNPROTECTED_DELEGATECALL_HAZARD,
                                pattern_category=PatternCategory.YUL_SECURITY_HAZARDS,
                                target_name=fn.name,
                                target_kind="function",
                                confidence=Confidence(score=0.95, evidences=evidences),
                                primary_location=fn.location,
                                evidences=evidences,
                            )
                        )
        return detections


class UnboundedCalldataLoopHazardRule(BaseRule):
    """Detects unbounded loop over calldata risking transaction out-of-gas step exhaustion."""

    LOOP_PATTERN = re.compile(r"\bfor\s*\{[\s\S]*?\}\s*1\s*\{[\s\S]*?\}\s*\{[\s\S]*?\bcalldataload\s*\(")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if self.LOOP_PATTERN.search(fn.body) or ("for {" in fn.body and "calldataload" in fn.body and "calldatasize()" not in fn.body):
                evidences = [
                    Evidence(
                        rule_code="HAZARD_UNBOUNDED_CALLDATA_LOOP",
                        description=f"Function '{fn.name}' iterates over calldata without strict calldatasize() bounds check, risking Out-Of-Gas DoS",
                        weight=0.88,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.UNBOUNDED_CALLDATA_LOOP_HAZARD,
                        pattern_category=PatternCategory.YUL_SECURITY_HAZARDS,
                        target_name=fn.name,
                        target_kind="function",
                        confidence=Confidence(score=0.88, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class DirtyHigherOrderBitsHazardRule(BaseRule):
    """Detects using sub-256-bit variables or booleans in equality comparisons without bit masking."""

    DIRTY_PATTERN = re.compile(r"\beq\s*\(\s*(calldataload\([^)]+\)|\w+)\s*,\s*(1|0)\s*\)")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if self.DIRTY_PATTERN.search(fn.body) and ("bool" in fn.raw_text or "uint8" in fn.raw_text):
                if "iszero(iszero" not in fn.body and "and(" not in fn.body:
                    evidences = [
                        Evidence(
                            rule_code="HAZARD_DIRTY_HIGHER_ORDER_BITS",
                            description=f"Function '{fn.name}' compares sub-word boolean/integer directly without cleaning upper bits (and(val, 0xff) / iszero(iszero(val)))",
                            weight=0.90,
                            location=fn.location,
                        )
                    ]
                    detections.append(
                        Detection(
                            pattern_type=PatternType.DIRTY_HIGHER_ORDER_BITS_HAZARD,
                            pattern_category=PatternCategory.YUL_SECURITY_HAZARDS,
                            target_name=fn.name,
                            target_kind="function",
                            confidence=Confidence(score=0.90, evidences=evidences),
                            primary_location=fn.location,
                            evidences=evidences,
                        )
                    )
        return detections


class MemoryCorruptionClobberHazardRule(BaseRule):
    """Detects writing to arbitrary memory addresses without referencing or updating the 0x40 pointer."""

    HIGH_MEM_STORE = re.compile(r"mstore\s*\(\s*(0x60|0x80|0xa0|0xc0|128|160)\s*,")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if self.HIGH_MEM_STORE.search(fn.body) and not fn.has_mload_40 and "mload(0x40)" not in fn.body:
                evidences = [
                    Evidence(
                        rule_code="HAZARD_MEMORY_CORRUPTION_CLOBBER",
                        description=f"Function '{fn.name}' writes to dynamic memory offsets (>= 0x60) without loading or updating the 0x40 free memory pointer",
                        weight=0.92,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.MEMORY_CORRUPTION_CLOBBER_HAZARD,
                        pattern_category=PatternCategory.YUL_SECURITY_HAZARDS,
                        target_name=fn.name,
                        target_kind="function",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections
