"""GoF Structural design pattern rules for Yul & EVM Assembly."""

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


class AdapterInterfaceCalldataRewriterRule(BaseRule):
    """Detects Adapter pattern transforming calldata layouts dynamically in assembly."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if ("adapt" in fn.name.lower() or "wrap" in fn.name.lower() or "rewrite" in fn.name.lower()) and ("calldatacopy" in fn.body or "mstore" in fn.body):
                evidences = [
                    Evidence(
                        rule_code="STRUCTURAL_ADAPTER_CALLDATA_REWRITER",
                        description=f"Function '{fn.name}' implements Adapter pattern transforming calldata layout for interface compatibility",
                        weight=0.90,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.ADAPTER_INTERFACE_CALLDATA_REWRITER,
                        pattern_category=PatternCategory.STRUCTURAL,
                        target_name=fn.name,
                        target_kind="function",
                        confidence=Confidence(score=0.90, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class BridgeCrossContractRelayRule(BaseRule):
    """Detects Bridge pattern relaying low-level call messages across contract boundaries."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if "bridge" in fn.name.lower() or "relay" in fn.name.lower() or "cross_call" in fn.name.lower():
                if "call(" in fn.body or "staticcall(" in fn.body:
                    evidences = [
                        Evidence(
                            rule_code="STRUCTURAL_BRIDGE_RELAY",
                            description=f"Function '{fn.name}' implements Bridge pattern relaying cross-contract messages",
                            weight=0.92,
                            location=fn.location,
                        )
                    ]
                    detections.append(
                        Detection(
                            pattern_type=PatternType.BRIDGE_CROSS_CONTRACT_RELAY,
                            pattern_category=PatternCategory.STRUCTURAL,
                            target_name=fn.name,
                            target_kind="function",
                            confidence=Confidence(score=0.92, evidences=evidences),
                            primary_location=fn.location,
                            evidences=evidences,
                        )
                    )
        return detections


class CompositeMulticallBatchRule(BaseRule):
    """Detects Composite pattern executing an array of heterogeneous contract calls in a loop."""

    MULTICALL_PATTERN = re.compile(r"\bfor\s*\{[\s\S]*?\}\s*lt\s*\([\s\S]*?\)\s*\{[\s\S]*?\}\s*\{[\s\S]*?\b(call|delegatecall)\s*\(")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if self.MULTICALL_PATTERN.search(fn.body) or ("multicall" in fn.name.lower() and "call(" in fn.body):
                evidences = [
                    Evidence(
                        rule_code="STRUCTURAL_COMPOSITE_MULTICALL",
                        description=f"Function '{fn.name}' implements Composite pattern executing batch call compositions in a single transaction",
                        weight=0.95,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.COMPOSITE_MULTICALL_BATCH,
                        pattern_category=PatternCategory.STRUCTURAL,
                        target_name=fn.name,
                        target_kind="function",
                        confidence=Confidence(score=0.95, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class DecoratorMemoryPaddingWrapperRule(BaseRule):
    """Detects Decorator pattern wrapping memory buffers with length prefixes and 32-byte alignment."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if ("pad" in fn.name.lower() or "wrap_bytes" in fn.name.lower() or "align_32" in fn.name.lower()) and "mstore" in fn.body:
                evidences = [
                    Evidence(
                        rule_code="STRUCTURAL_DECORATOR_MEMORY_PADDING",
                        description=f"Function '{fn.name}' implements Decorator pattern augmenting memory buffers with length headers and alignment",
                        weight=0.90,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.DECORATOR_MEMORY_PADDING_WRAPPER,
                        pattern_category=PatternCategory.STRUCTURAL,
                        target_name=fn.name,
                        target_kind="function",
                        confidence=Confidence(score=0.90, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class FacadeSelectorRouterRule(BaseRule):
    """Detects Facade pattern routing external calls through a unified 4-byte jump table."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if "switch" in fn.body and "case" in fn.body and ("calldataload" in fn.body or "selector" in fn.name.lower()):
                evidences = [
                    Evidence(
                        rule_code="STRUCTURAL_FACADE_SELECTOR_ROUTER",
                        description=f"Function '{fn.name}' implements Facade pattern routing external calls via unified selector jump table",
                        weight=0.92,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.FACADE_SELECTOR_ROUTER,
                        pattern_category=PatternCategory.STRUCTURAL,
                        target_name=fn.name,
                        target_kind="function",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class FlyweightImmutableCodecopySlotRule(BaseRule):
    """Detects Flyweight pattern reading shared immutable constants directly from deployed code via codecopy."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if ("immutable" in fn.name.lower() or "constant" in fn.name.lower()) and (fn.has_codecopy or "codecopy(" in fn.body):
                evidences = [
                    Evidence(
                        rule_code="STRUCTURAL_FLYWEIGHT_IMMUTABLE_CODECOPY",
                        description=f"Function '{fn.name}' implements Flyweight pattern reading immutable parameters directly from codecopy",
                        weight=0.92,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.FLYWEIGHT_IMMUTABLE_CODECOPY_SLOT,
                        pattern_category=PatternCategory.STRUCTURAL,
                        target_name=fn.name,
                        target_kind="function",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class ProxyDelegatecallForwarderRule(BaseRule):
    """Detects Transparent/UUPS/Diamond proxy pattern forwarding via delegatecall and returning returndata."""

    PROXY_PATTERN = re.compile(r"delegatecall\s*\([\s\S]*?\)\s*returndatacopy\s*\([\s\S]*?\)\s*(return|revert)\s*\(")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if self.PROXY_PATTERN.search(fn.body) or (fn.has_delegatecall and "returndatacopy" in fn.body):
                evidences = [
                    Evidence(
                        rule_code="STRUCTURAL_PROXY_DELEGATECALL_FORWARDER",
                        description=f"Function '{fn.name}' implements Proxy pattern forwarding calls via delegatecall and copying returndata",
                        weight=0.95,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.PROXY_DELEGATECALL_FORWARDER,
                        pattern_category=PatternCategory.STRUCTURAL,
                        target_name=fn.name,
                        target_kind="function",
                        confidence=Confidence(score=0.95, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections
