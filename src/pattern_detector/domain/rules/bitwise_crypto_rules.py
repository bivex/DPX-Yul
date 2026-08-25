"""Bitwise Arithmetic, Cryptography & Math rules for Yul & EVM Assembly."""

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


class BitwiseMaskingCompressionRule(BaseRule):
    """Detects bitwise shift and mask operations extracting or packing compressed sub-words."""

    MASK_PATTERN = re.compile(r"\band\s*\(\s*\w+\s*,\s*(0x[0-9a-fA-F]+)\s*\)")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if self.MASK_PATTERN.search(fn.body) and ("shr(" in fn.body or "shl(" in fn.body or "0xff" in fn.body):
                evidences = [
                    Evidence(
                        rule_code="YUL_BITWISE_MASKING",
                        description=f"Function '{fn.name}' performs bitwise masking and compression on EVM words",
                        weight=0.90,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.BITWISE_MASKING_COMPRESSION,
                        pattern_category=PatternCategory.BITWISE_MATH_CRYPTO,
                        target_name=fn.name,
                        target_kind="function",
                        confidence=Confidence(score=0.90, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class Keccak256HashSlotDerivationRule(BaseRule):
    """Detects calculating mapping storage slots or EIP-712 typed hashes using keccak256(ptr, len)."""

    KECCAK_PATTERN = re.compile(r"\bkeccak256\s*\(")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if fn.has_keccak or self.KECCAK_PATTERN.search(fn.body):
                evidences = [
                    Evidence(
                        rule_code="YUL_KECCAK256_HASH_SLOT",
                        description=f"Function '{fn.name}' derives storage slots or cryptographic digests via keccak256()",
                        weight=0.95,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.KECCAK256_HASH_SLOT_DERIVATION,
                        pattern_category=PatternCategory.BITWISE_MATH_CRYPTO,
                        target_name=fn.name,
                        target_kind="function",
                        confidence=Confidence(score=0.95, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class OverflowFreeModuloArithmeticRule(BaseRule):
    """Detects native EVM arbitrary-precision modulo operations using addmod and mulmod."""

    MOD_PATTERN = re.compile(r"\b(addmod|mulmod)\s*\(")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if self.MOD_PATTERN.search(fn.body):
                evidences = [
                    Evidence(
                        rule_code="YUL_MODULO_ARITHMETIC",
                        description=f"Function '{fn.name}' executes overflow-free modular arithmetic via addmod/mulmod",
                        weight=0.95,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.OVERFLOW_FREE_MODULO_ARITHMETIC,
                        pattern_category=PatternCategory.BITWISE_MATH_CRYPTO,
                        target_name=fn.name,
                        target_kind="function",
                        confidence=Confidence(score=0.95, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections
