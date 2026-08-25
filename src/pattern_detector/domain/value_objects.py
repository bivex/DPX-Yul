"""Domain Value Objects and Enumerations for Yul & EVM Assembly."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class PatternCategory(str, Enum):
    """Categorization of Yul and EVM Assembly architectural patterns and hazards."""

    YUL_IDIOMATIC_EVM = "yul_idiomatic_evm"
    LOW_LEVEL_CALLS_METAPROGRAMMING = "low_level_calls_metaprogramming"
    BITWISE_MATH_CRYPTO = "bitwise_math_crypto"
    CREATIONAL = "creational"
    STRUCTURAL = "structural"
    BEHAVIORAL = "behavioral"
    YUL_SECURITY_HAZARDS = "yul_security_hazards"
    PRINCIPLE = "principle"


class PatternType(str, Enum):
    """Catalog of 43 Yul and EVM Assembly architectural and security patterns."""

    # 1. Yul Idiomatic, EVM Memory & Storage Architecture (6)
    YUL_OBJECT_RUNTIME_HIERARCHY = "yul_object_runtime_hierarchy"
    FREE_MEMORY_POINTER_MANAGEMENT = "free_memory_pointer_management"
    TRANSIENT_STORAGE_EIP1153 = "transient_storage_eip1153"
    CUSTOM_FOURBYTE_SELECTOR_DISPATCHER = "custom_fourbyte_selector_dispatcher"
    STORAGE_SLOT_BITFIELD_PACKING = "storage_slot_bitfield_packing"
    CUSTOM_ERROR_MEMORY_REVERT = "custom_error_memory_revert"

    # 2. Low-Level Call Dispatch & Metaprogramming (4)
    DELEGATECALL_FORWARDING_PROXY = "delegatecall_forwarding_proxy"
    DETERMINISTIC_CREATE2_DEPLOYER = "deterministic_create2_deployer"
    STATICCALL_VIEW_QUERY = "staticcall_view_query"
    CALLDATA_ZERO_COPY_STREAMING = "calldata_zero_copy_streaming"

    # 3. Bitwise Arithmetic, Cryptography & Math (3)
    BITWISE_MASKING_COMPRESSION = "bitwise_masking_compression"
    KECCAK256_HASH_SLOT_DERIVATION = "keccak256_hash_slot_derivation"
    OVERFLOW_FREE_MODULO_ARITHMETIC = "overflow_free_modulo_arithmetic"

    # 4. Creational Patterns (5/5)
    SINGLETON_STORAGE_SLOT_VAULT = "singleton_storage_slot_vault"
    FACTORY_CREATE2_INSTANCE_SPAWNER = "factory_create2_instance_spawner"
    ABSTRACT_FACTORY_POOL_DISPATCHER = "abstract_factory_pool_dispatcher"
    BUILDER_MEMORY_CALLDATA_ENCODER = "builder_memory_calldata_encoder"
    PROTOTYPE_BYTECODE_CLONE_PACKER = "prototype_bytecode_clone_packer"

    # 5. Structural Patterns (7/7)
    ADAPTER_INTERFACE_CALLDATA_REWRITER = "adapter_interface_calldata_rewriter"
    BRIDGE_CROSS_CONTRACT_RELAY = "bridge_cross_contract_relay"
    COMPOSITE_MULTICALL_BATCH = "composite_multicall_batch"
    DECORATOR_MEMORY_PADDING_WRAPPER = "decorator_memory_padding_wrapper"
    FACADE_SELECTOR_ROUTER = "facade_selector_router"
    FLYWEIGHT_IMMUTABLE_CODECOPY_SLOT = "flyweight_immutable_codecopy_slot"
    PROXY_DELEGATECALL_FORWARDER = "proxy_delegatecall_forwarder"

    # 6. Behavioral Patterns (11/11)
    CHAIN_OF_RESPONSIBILITY_AUTH_FILTER = "chain_of_responsibility_auth_filter"
    COMMAND_RAW_CALL_PAYLOAD = "command_raw_call_payload"
    INTERPRETER_BYTECODE_EVALUATOR = "interpreter_bytecode_evaluator"
    ITERATOR_CALLDATA_OFFSET_SCAN = "iterator_calldata_offset_scan"
    MEDIATOR_ESCROW_ATOMIC_SWAP = "mediator_escrow_atomic_swap"
    MEMENTO_TRANSIENT_SLOT_CHECKPOINT = "memento_transient_slot_checkpoint"
    OBSERVER_LOG_TOPIC_EMISSION = "observer_log_topic_emission"
    STATE_MACHINE_SLOT_LIFECYCLE = "state_machine_slot_lifecycle"
    STRATEGY_JUMP_TABLE_INJECTION = "strategy_jump_table_injection"
    TEMPLATE_METHOD_HOOK_LIFECYCLE = "template_method_hook_lifecycle"
    VISITOR_RETURN_DATA_RECEIVER = "visitor_return_data_receiver"

    # 7. Yul & EVM Assembly Security Hazards (4)
    UNPROTECTED_DELEGATECALL_HAZARD = "unprotected_delegatecall_hazard"
    UNBOUNDED_CALLDATA_LOOP_HAZARD = "unbounded_calldata_loop_hazard"
    DIRTY_HIGHER_ORDER_BITS_HAZARD = "dirty_higher_order_bits_hazard"
    MEMORY_CORRUPTION_CLOBBER_HAZARD = "memory_corruption_clobber_hazard"

    # 8. SOLID Principles & Smells (3)
    MONOLITHIC_YUL_OBJECT_SRP = "monolithic_yul_object_srp"
    FAT_MEMORY_STRUCT_ISP = "fat_memory_struct_isp"
    HARDCODED_STORAGE_SLOT_OCP = "hardcoded_storage_slot_ocp"


class ConfidenceLevel(str, Enum):
    """Categorized confidence level."""

    VERY_HIGH = "VERY_HIGH"  # >= 0.90
    HIGH = "HIGH"            # >= 0.75
    MEDIUM = "MEDIUM"        # >= 0.50
    LOW = "LOW"              # < 0.50


@dataclass(frozen=True)
class SourceLocation:
    """Source file location descriptor."""

    file_path: str
    line: int
    column: int = 1
    end_line: int | None = None

    def __str__(self) -> str:
        if self.end_line and self.end_line != self.line:
            return f"{self.file_path}:{self.line}-{self.end_line}:{self.column}"
        return f"{self.file_path}:{self.line}:{self.column}"


@dataclass(frozen=True)
class Evidence:
    """Atomic piece of evidence supporting pattern detection."""

    rule_code: str
    description: str
    weight: float
    location: SourceLocation | None = None


@dataclass
class Confidence:
    """Detection confidence score with supporting evidence trail."""

    score: float
    evidences: list[Evidence] = field(default_factory=list)

    @property
    def level(self) -> ConfidenceLevel:
        if self.score >= 0.90:
            return ConfidenceLevel.VERY_HIGH
        if self.score >= 0.75:
            return ConfidenceLevel.HIGH
        if self.score >= 0.50:
            return ConfidenceLevel.MEDIUM
        return ConfidenceLevel.LOW

    @property
    def percentage_str(self) -> str:
        return f"{int(self.score * 100)}%"
