"""Rules registry and aggregation factory for Yul & EVM Assembly pattern detector."""

from __future__ import annotations

from pattern_detector.domain.rules.base import BaseRule
from pattern_detector.domain.rules.behavioral_rules import (
    ChainOfResponsibilityAuthFilterRule,
    CommandRawCallPayloadRule,
    InterpreterBytecodeEvaluatorRule,
    IteratorCalldataOffsetScanRule,
    MediatorEscrowAtomicSwapRule,
    MementoTransientSlotCheckpointRule,
    ObserverLogTopicEmissionRule,
    StateMachineSlotLifecycleRule,
    StrategyJumpTableInjectionRule,
    TemplateMethodHookLifecycleRule,
    VisitorReturnDataReceiverRule,
)
from pattern_detector.domain.rules.bitwise_crypto_rules import (
    BitwiseMaskingCompressionRule,
    Keccak256HashSlotDerivationRule,
    OverflowFreeModuloArithmeticRule,
)
from pattern_detector.domain.rules.creational_rules import (
    AbstractFactoryPoolDispatcherRule,
    BuilderMemoryCalldataEncoderRule,
    FactoryCreate2InstanceSpawnerRule,
    PrototypeBytecodeClonePackerRule,
    SingletonStorageSlotVaultRule,
)
from pattern_detector.domain.rules.idiomatic_rules import (
    CustomErrorMemoryRevertRule,
    CustomFourbyteSelectorDispatcherRule,
    FreeMemoryPointerManagementRule,
    StorageSlotBitfieldPackingRule,
    TransientStorageEip1153Rule,
    YulObjectRuntimeHierarchyRule,
)
from pattern_detector.domain.rules.low_level_calls_rules import (
    CalldataZeroCopyStreamingRule,
    DelegatecallForwardingProxyRule,
    DeterministicCreate2DeployerRule,
    StaticcallViewQueryRule,
)
from pattern_detector.domain.rules.security_rules import (
    DirtyHigherOrderBitsHazardRule,
    MemoryCorruptionClobberHazardRule,
    UnboundedCalldataLoopHazardRule,
    UnprotectedDelegatecallHazardRule,
)
from pattern_detector.domain.rules.solid_principles_rules import (
    FatMemoryStructIspRule,
    HardcodedStorageSlotOcpRule,
    MonolithicYulObjectSrpRule,
)
from pattern_detector.domain.rules.structural_rules import (
    AdapterInterfaceCalldataRewriterRule,
    BridgeCrossContractRelayRule,
    CompositeMulticallBatchRule,
    DecoratorMemoryPaddingWrapperRule,
    FacadeSelectorRouterRule,
    FlyweightImmutableCodecopySlotRule,
    ProxyDelegatecallForwarderRule,
)

DEFAULT_RULES: list[type[BaseRule]] = [
    # 1. Yul Idiomatic, EVM Memory & Storage Architecture (6)
    YulObjectRuntimeHierarchyRule,
    FreeMemoryPointerManagementRule,
    TransientStorageEip1153Rule,
    CustomFourbyteSelectorDispatcherRule,
    StorageSlotBitfieldPackingRule,
    CustomErrorMemoryRevertRule,

    # 2. Low-Level Call Dispatch & Metaprogramming (4)
    DelegatecallForwardingProxyRule,
    DeterministicCreate2DeployerRule,
    StaticcallViewQueryRule,
    CalldataZeroCopyStreamingRule,

    # 3. Bitwise Arithmetic, Cryptography & Math (3)
    BitwiseMaskingCompressionRule,
    Keccak256HashSlotDerivationRule,
    OverflowFreeModuloArithmeticRule,

    # 4. Creational Patterns (5/5)
    SingletonStorageSlotVaultRule,
    FactoryCreate2InstanceSpawnerRule,
    AbstractFactoryPoolDispatcherRule,
    BuilderMemoryCalldataEncoderRule,
    PrototypeBytecodeClonePackerRule,

    # 5. Structural Patterns (7/7)
    AdapterInterfaceCalldataRewriterRule,
    BridgeCrossContractRelayRule,
    CompositeMulticallBatchRule,
    DecoratorMemoryPaddingWrapperRule,
    FacadeSelectorRouterRule,
    FlyweightImmutableCodecopySlotRule,
    ProxyDelegatecallForwarderRule,

    # 6. Behavioral Patterns (11/11)
    ChainOfResponsibilityAuthFilterRule,
    CommandRawCallPayloadRule,
    InterpreterBytecodeEvaluatorRule,
    IteratorCalldataOffsetScanRule,
    MediatorEscrowAtomicSwapRule,
    MementoTransientSlotCheckpointRule,
    ObserverLogTopicEmissionRule,
    StateMachineSlotLifecycleRule,
    StrategyJumpTableInjectionRule,
    TemplateMethodHookLifecycleRule,
    VisitorReturnDataReceiverRule,

    # 7. Yul & EVM Assembly Security Hazards (4)
    UnprotectedDelegatecallHazardRule,
    UnboundedCalldataLoopHazardRule,
    DirtyHigherOrderBitsHazardRule,
    MemoryCorruptionClobberHazardRule,

    # 8. SOLID Principles & Smells (3)
    MonolithicYulObjectSrpRule,
    FatMemoryStructIspRule,
    HardcodedStorageSlotOcpRule,
]


def get_default_rules() -> list[BaseRule]:
    """Instantiate and return full suite of default Yul rules."""
    return [rule_cls() for rule_cls in DEFAULT_RULES]
