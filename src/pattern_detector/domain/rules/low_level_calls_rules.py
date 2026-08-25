"""Low-Level Call Dispatch & Metaprogramming rules for Yul & EVM Assembly."""

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


class DelegatecallForwardingProxyRule(BaseRule):
    """Detects assembly delegatecall forwarding pattern preserving caller context and returndata."""

    DELEGATE_PATTERN = re.compile(r"\bdelegatecall\s*\(")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if fn.has_delegatecall or self.DELEGATE_PATTERN.search(fn.body):
                evidences = [
                    Evidence(
                        rule_code="YUL_DELEGATECALL_FORWARDING",
                        description=f"Function '{fn.name}' executes delegatecall proxy forwarding in EVM assembly",
                        weight=0.95,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.DELEGATECALL_FORWARDING_PROXY,
                        pattern_category=PatternCategory.LOW_LEVEL_CALLS_METAPROGRAMMING,
                        target_name=fn.name,
                        target_kind="function",
                        confidence=Confidence(score=0.95, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class DeterministicCreate2DeployerRule(BaseRule):
    """Detects on-chain deployment using create2 opcode with explicit salt and bytecode pointers."""

    CREATE2_PATTERN = re.compile(r"\bcreate2\s*\(")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if fn.has_create2 or self.CREATE2_PATTERN.search(fn.body):
                evidences = [
                    Evidence(
                        rule_code="YUL_DETERMINISTIC_CREATE2",
                        description=f"Function '{fn.name}' deploys child bytecode deterministically via create2 opcode",
                        weight=0.95,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.DETERMINISTIC_CREATE2_DEPLOYER,
                        pattern_category=PatternCategory.LOW_LEVEL_CALLS_METAPROGRAMMING,
                        target_name=fn.name,
                        target_kind="function",
                        confidence=Confidence(score=0.95, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class StaticcallViewQueryRule(BaseRule):
    """Detects read-only external contract invocation using staticcall."""

    STATICCALL_PATTERN = re.compile(r"\bstaticcall\s*\(")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if fn.has_staticcall or self.STATICCALL_PATTERN.search(fn.body):
                evidences = [
                    Evidence(
                        rule_code="YUL_STATICCALL_VIEW",
                        description=f"Function '{fn.name}' executes read-only staticcall invocation ensuring state immutability",
                        weight=0.92,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.STATICCALL_VIEW_QUERY,
                        pattern_category=PatternCategory.LOW_LEVEL_CALLS_METAPROGRAMMING,
                        target_name=fn.name,
                        target_kind="function",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class CalldataZeroCopyStreamingRule(BaseRule):
    """Detects calldataload streaming loops bypassing memory allocation for high-throughput batching."""

    STREAM_PATTERN = re.compile(r"\bfor\s*\{[\s\S]*?\}\s*lt\s*\([\s\S]*?\)\s*\{[\s\S]*?\}\s*\{[\s\S]*?\bcalldataload\s*\(")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if self.STREAM_PATTERN.search(fn.body) or ("calldataload" in fn.body and "for {" in fn.body and "mstore" not in fn.body):
                evidences = [
                    Evidence(
                        rule_code="YUL_CALLDATA_ZERO_COPY_STREAMING",
                        description=f"Function '{fn.name}' streams calldata directly in a loop without intermediate memory copies",
                        weight=0.92,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.CALLDATA_ZERO_COPY_STREAMING,
                        pattern_category=PatternCategory.LOW_LEVEL_CALLS_METAPROGRAMMING,
                        target_name=fn.name,
                        target_kind="function",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections
