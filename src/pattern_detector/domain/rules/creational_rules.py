"""GoF Creational design pattern rules for Yul & EVM Assembly."""

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


class SingletonStorageSlotVaultRule(BaseRule):
    """Detects Singleton pattern managing state at a deterministic keccak256 namespace storage slot."""

    SLOT_CONST_PATTERN = re.compile(r"(0x[0-9a-fA-F]{64}|keccak256\s*\([^)]+\))")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if (fn.has_sload or fn.has_sstore) and self.SLOT_CONST_PATTERN.search(fn.body):
                evidences = [
                    Evidence(
                        rule_code="CREATIONAL_SINGLETON_STORAGE_SLOT",
                        description=f"Function '{fn.name}' accesses state at a dedicated deterministic namespace storage slot (ERC-7201 / Singleton)",
                        weight=0.90,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.SINGLETON_STORAGE_SLOT_VAULT,
                        pattern_category=PatternCategory.CREATIONAL,
                        target_name=fn.name,
                        target_kind="function",
                        confidence=Confidence(score=0.90, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class FactoryCreate2InstanceSpawnerRule(BaseRule):
    """Detects Factory pattern deploying child contracts on-chain with deterministic salt."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if fn.has_create2 or "create2(" in fn.body:
                evidences = [
                    Evidence(
                        rule_code="CREATIONAL_FACTORY_CREATE2",
                        description=f"Function '{fn.name}' implements Factory pattern instantiating child contracts via create2 opcode",
                        weight=0.95,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.FACTORY_CREATE2_INSTANCE_SPAWNER,
                        pattern_category=PatternCategory.CREATIONAL,
                        target_name=fn.name,
                        target_kind="function",
                        confidence=Confidence(score=0.95, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class AbstractFactoryPoolDispatcherRule(BaseRule):
    """Detects Abstract Factory pattern deploying liquidity pools or vaults from parametric templates."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            is_pool_name = any(kw in fn.name.lower() for kw in ("create_pool", "deploy_pool", "create_vault", "deploy_vault", "create_pair"))
            if is_pool_name and ("create" in fn.body or "create2" in fn.body):
                evidences = [
                    Evidence(
                        rule_code="CREATIONAL_ABSTRACT_FACTORY_POOL",
                        description=f"Function '{fn.name}' implements Abstract Factory pattern creating parameterized pool/vault instances",
                        weight=0.92,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.ABSTRACT_FACTORY_POOL_DISPATCHER,
                        pattern_category=PatternCategory.CREATIONAL,
                        target_name=fn.name,
                        target_kind="function",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class BuilderMemoryCalldataEncoderRule(BaseRule):
    """Detects Builder pattern incrementally constructing structured ABI-encoded memory payloads."""

    BUILDER_PATTERN = re.compile(r"mstore\s*\(\s*add\s*\(\s*\w+\s*,\s*0x[0-9a-fA-F]+\s*\)\s*,\s*\w+\s*\)")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            matches = self.BUILDER_PATTERN.findall(fn.body)
            if len(matches) >= 2 or ("abi_encode" in fn.name.lower() or "build_calldata" in fn.name.lower()):
                evidences = [
                    Evidence(
                        rule_code="CREATIONAL_BUILDER_MEMORY_ENCODER",
                        description=f"Function '{fn.name}' implements Builder pattern assembling structured ABI calldata in memory",
                        weight=0.90,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.BUILDER_MEMORY_CALLDATA_ENCODER,
                        pattern_category=PatternCategory.CREATIONAL,
                        target_name=fn.name,
                        target_kind="function",
                        confidence=Confidence(score=0.90, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class PrototypeBytecodeClonePackerRule(BaseRule):
    """Detects Prototype pattern cloning contract bytecode via codecopy / extcodecopy (e.g. EIP-1167)."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if fn.has_codecopy or "extcodecopy(" in fn.body or "codecopy(" in fn.body:
                if "clone" in fn.name.lower() or "proxy" in fn.name.lower() or "deploy" in fn.name.lower():
                    evidences = [
                        Evidence(
                            rule_code="CREATIONAL_PROTOTYPE_BYTECODE_CLONE",
                            description=f"Function '{fn.name}' implements Prototype pattern cloning runtime bytecode via codecopy",
                            weight=0.92,
                            location=fn.location,
                        )
                    ]
                    detections.append(
                        Detection(
                            pattern_type=PatternType.PROTOTYPE_BYTECODE_CLONE_PACKER,
                            pattern_category=PatternCategory.CREATIONAL,
                            target_name=fn.name,
                            target_kind="function",
                            confidence=Confidence(score=0.92, evidences=evidences),
                            primary_location=fn.location,
                            evidences=evidences,
                        )
                    )
        return detections
