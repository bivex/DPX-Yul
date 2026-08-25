"""GoF Behavioral design pattern rules for Yul & EVM Assembly."""

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


class ChainOfResponsibilityAuthFilterRule(BaseRule):
    """Detects sequenced validation checks in assembly (caller == owner, !paused, deadline >= block.timestamp)."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if ("caller()" in fn.body or "caller" in fn.body) and ("timestamp()" in fn.body or "revert(" in fn.body or "iszero" in fn.body):
                if "require" in fn.name.lower() or "auth" in fn.name.lower() or "check" in fn.name.lower() or "validate" in fn.name.lower():
                    evidences = [
                        Evidence(
                            rule_code="BEHAVIORAL_CHAIN_OF_RESPONSIBILITY_AUTH",
                            description=f"Function '{fn.name}' implements Chain of Responsibility filtering authorization and execution preconditions",
                            weight=0.90,
                            location=fn.location,
                        )
                    ]
                    detections.append(
                        Detection(
                            pattern_type=PatternType.CHAIN_OF_RESPONSIBILITY_AUTH_FILTER,
                            pattern_category=PatternCategory.BEHAVIORAL,
                            target_name=fn.name,
                            target_kind="function",
                            confidence=Confidence(score=0.90, evidences=evidences),
                            primary_location=fn.location,
                            evidences=evidences,
                        )
                    )
        return detections


class CommandRawCallPayloadRule(BaseRule):
    """Detects Command pattern packaging { target, value, data_ptr, data_len } for delayed execution."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if ("execute_call" in fn.name.lower() or "dispatch_call" in fn.name.lower() or "run_command" in fn.name.lower()) and "call(" in fn.body:
                evidences = [
                    Evidence(
                        rule_code="BEHAVIORAL_COMMAND_RAW_CALL",
                        description=f"Function '{fn.name}' implements Command pattern encapsulating raw call execution payloads",
                        weight=0.92,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.COMMAND_RAW_CALL_PAYLOAD,
                        pattern_category=PatternCategory.BEHAVIORAL,
                        target_name=fn.name,
                        target_kind="function",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class InterpreterBytecodeEvaluatorRule(BaseRule):
    """Detects Interpreter pattern evaluating custom DSL instructions or order matching scripts in a loop."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if ("eval" in fn.name.lower() or "interpret" in fn.name.lower() or "exec_op" in fn.name.lower()) and ("switch" in fn.body or "for {" in fn.body):
                evidences = [
                    Evidence(
                        rule_code="BEHAVIORAL_INTERPRETER_EVALUATOR",
                        description=f"Function '{fn.name}' implements Interpreter pattern evaluating custom opcode instructions in an assembly loop",
                        weight=0.92,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.INTERPRETER_BYTECODE_EVALUATOR,
                        pattern_category=PatternCategory.BEHAVIORAL,
                        target_name=fn.name,
                        target_kind="function",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class IteratorCalldataOffsetScanRule(BaseRule):
    """Detects cursor-based iterator scanning packed calldata in 32-byte strides (add(offset, 0x20))."""

    STRIDE_PATTERN = re.compile(r"add\s*\(\s*\w+\s*,\s*(0x20|32)\s*\)")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if "for {" in fn.body and self.STRIDE_PATTERN.search(fn.body) and ("calldataload" in fn.body or "mload" in fn.body):
                evidences = [
                    Evidence(
                        rule_code="BEHAVIORAL_ITERATOR_OFFSET_SCAN",
                        description=f"Function '{fn.name}' implements Iterator pattern scanning calldata/memory words in 32-byte cursor strides",
                        weight=0.92,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.ITERATOR_CALLDATA_OFFSET_SCAN,
                        pattern_category=PatternCategory.BEHAVIORAL,
                        target_name=fn.name,
                        target_kind="function",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class MediatorEscrowAtomicSwapRule(BaseRule):
    """Detects Mediator pattern coordinating multi-token transfers atomically between trading counterparties."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if ("escrow" in fn.name.lower() or "swap" in fn.name.lower() or "settle" in fn.name.lower()) and "call(" in fn.body:
                evidences = [
                    Evidence(
                        rule_code="BEHAVIORAL_MEDIATOR_ESCROW_SWAP",
                        description=f"Function '{fn.name}' implements Mediator pattern coordinating atomic asset settlement between counterparties",
                        weight=0.90,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.MEDIATOR_ESCROW_ATOMIC_SWAP,
                        pattern_category=PatternCategory.BEHAVIORAL,
                        target_name=fn.name,
                        target_kind="function",
                        confidence=Confidence(score=0.90, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class MementoTransientSlotCheckpointRule(BaseRule):
    """Detects Memento pattern snapshotting and restoring state via transient storage (tstore / tload)."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if (fn.has_tstore and fn.has_tload) or ("tstore(" in fn.body and "tload(" in fn.body):
                if "checkpoint" in fn.name.lower() or "snapshot" in fn.name.lower() or "lock" in fn.name.lower() or "guard" in fn.name.lower():
                    evidences = [
                        Evidence(
                            rule_code="BEHAVIORAL_MEMENTO_TRANSIENT_CHECKPOINT",
                            description=f"Function '{fn.name}' implements Memento pattern snapshotting state into transient storage slots",
                            weight=0.95,
                            location=fn.location,
                        )
                    ]
                    detections.append(
                        Detection(
                            pattern_type=PatternType.MEMENTO_TRANSIENT_SLOT_CHECKPOINT,
                            pattern_category=PatternCategory.BEHAVIORAL,
                            target_name=fn.name,
                            target_kind="function",
                            confidence=Confidence(score=0.95, evidences=evidences),
                            primary_location=fn.location,
                            evidences=evidences,
                        )
                    )
        return detections


class ObserverLogTopicEmissionRule(BaseRule):
    """Detects Observer pattern emitting structured EVM logs (log1, log2, log3, log4) for indexers."""

    LOG_PATTERN = re.compile(r"\b(log0|log1|log2|log3|log4)\s*\(")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if fn.has_log or self.LOG_PATTERN.search(fn.body):
                evidences = [
                    Evidence(
                        rule_code="BEHAVIORAL_OBSERVER_LOG_EMISSION",
                        description=f"Function '{fn.name}' implements Observer pattern broadcasting state change events via EVM log topics",
                        weight=0.95,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.OBSERVER_LOG_TOPIC_EMISSION,
                        pattern_category=PatternCategory.BEHAVIORAL,
                        target_name=fn.name,
                        target_kind="function",
                        confidence=Confidence(score=0.95, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class StateMachineSlotLifecycleRule(BaseRule):
    """Detects Finite State Machine tracking and transitioning lifecycle states stored in storage slots."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if ("state" in fn.name.lower() or "phase" in fn.name.lower() or "status" in fn.name.lower()) and (fn.has_sload and fn.has_sstore):
                evidences = [
                    Evidence(
                        rule_code="BEHAVIORAL_STATE_MACHINE_SLOT",
                        description=f"Function '{fn.name}' implements Finite State Machine transitions stored in dedicated storage slots",
                        weight=0.90,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.STATE_MACHINE_SLOT_LIFECYCLE,
                        pattern_category=PatternCategory.BEHAVIORAL,
                        target_name=fn.name,
                        target_kind="function",
                        confidence=Confidence(score=0.90, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class StrategyJumpTableInjectionRule(BaseRule):
    """Detects Strategy pattern selecting algorithmic execution branches dynamically via switch or lookup tables."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if ("strategy" in fn.name.lower() or "mode" in fn.name.lower() or "calc" in fn.name.lower()) and "switch" in fn.body:
                evidences = [
                    Evidence(
                        rule_code="BEHAVIORAL_STRATEGY_JUMP_TABLE",
                        description=f"Function '{fn.name}' implements Strategy pattern dispatching execution paths dynamically",
                        weight=0.92,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.STRATEGY_JUMP_TABLE_INJECTION,
                        pattern_category=PatternCategory.BEHAVIORAL,
                        target_name=fn.name,
                        target_kind="function",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class TemplateMethodHookLifecycleRule(BaseRule):
    """Detects Template Method pattern coordinating pre-check, execution, and post-hook lifecycle."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if ("before_" in fn.body or "after_" in fn.body or "pre_" in fn.body or "post_" in fn.body) and ("call(" in fn.body or "delegatecall(" in fn.body):
                evidences = [
                    Evidence(
                        rule_code="BEHAVIORAL_TEMPLATE_METHOD_HOOK",
                        description=f"Function '{fn.name}' implements Template Method lifecycle with pre/post execution hooks",
                        weight=0.92,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.TEMPLATE_METHOD_HOOK_LIFECYCLE,
                        pattern_category=PatternCategory.BEHAVIORAL,
                        target_name=fn.name,
                        target_kind="function",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class VisitorReturnDataReceiverRule(BaseRule):
    """Detects Visitor pattern inspecting and unpacking external call returndata via returndatacopy."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if "returndatacopy(" in fn.body and "returndatasize()" in fn.body:
                evidences = [
                    Evidence(
                        rule_code="BEHAVIORAL_VISITOR_RETURNDATA_RECEIVER",
                        description=f"Function '{fn.name}' implements Visitor pattern unpacking arbitrary return data buffers",
                        weight=0.92,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.VISITOR_RETURN_DATA_RECEIVER,
                        pattern_category=PatternCategory.BEHAVIORAL,
                        target_name=fn.name,
                        target_kind="function",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections
