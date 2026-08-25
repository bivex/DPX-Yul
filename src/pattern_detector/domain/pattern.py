"""Pattern metadata catalog and definitions for Yul & EVM Assembly."""

from __future__ import annotations

from dataclasses import dataclass
from pattern_detector.domain.value_objects import PatternCategory, PatternType


@dataclass(frozen=True)
class PatternDefinition:
    """Detailed metadata for a Yul / EVM Assembly architectural pattern or hazard."""

    type: PatternType
    name: str
    category: PatternCategory
    description: str
    recommendation: str | None = None
    yul_version: str = "Yul 0.8.x - 0.8.28+ / Cancun EIP-1153"


PATTERN_CATALOG: dict[PatternType, PatternDefinition] = {
    # 1. Yul Idiomatic, EVM Memory & Storage Architecture (6)
    PatternType.YUL_OBJECT_RUNTIME_HIERARCHY: PatternDefinition(
        type=PatternType.YUL_OBJECT_RUNTIME_HIERARCHY,
        name="Yul Object Runtime Hierarchy",
        category=PatternCategory.YUL_IDIOMATIC_EVM,
        description="Nested Yul object declaring constructor init code and deployed runtime object (object 'Contract_deployed').",
        recommendation="Maintain clean separation between deployment constructor logic and runtime dispatch logic.",
    ),
    PatternType.FREE_MEMORY_POINTER_MANAGEMENT: PatternDefinition(
        type=PatternType.FREE_MEMORY_POINTER_MANAGEMENT,
        name="Free Memory Pointer Management",
        category=PatternCategory.YUL_IDIOMATIC_EVM,
        description="Standard EVM memory allocation loading and updating the 0x40 free memory pointer (mload(0x40), mstore(0x40, ...)).",
        recommendation="Always update the 0x40 pointer when allocating dynamic buffers to avoid memory clobbering.",
    ),
    PatternType.TRANSIENT_STORAGE_EIP1153: PatternDefinition(
        type=PatternType.TRANSIENT_STORAGE_EIP1153,
        name="Transient Storage (EIP-1153)",
        category=PatternCategory.YUL_IDIOMATIC_EVM,
        description="Temporary transaction-scoped storage utilizing tstore and tload opcodes for gas-efficient reentrancy locks and transient contexts.",
        recommendation="Ensure transient storage slots are cleared or reset before transaction completion to avoid stale state in multicalls.",
    ),
    PatternType.CUSTOM_FOURBYTE_SELECTOR_DISPATCHER: PatternDefinition(
        type=PatternType.CUSTOM_FOURBYTE_SELECTOR_DISPATCHER,
        name="Custom 4-Byte Function Selector Dispatcher",
        category=PatternCategory.YUL_IDIOMATIC_EVM,
        description="Direct calldata extraction of function selector (shr(224, calldataload(0))) with optimized switch-case branching.",
        recommendation="Order function selectors by execution frequency or use binary search dispatching for high-throughput contracts.",
    ),
    PatternType.STORAGE_SLOT_BITFIELD_PACKING: PatternDefinition(
        type=PatternType.STORAGE_SLOT_BITFIELD_PACKING,
        name="Storage Slot Bitfield Packing",
        category=PatternCategory.YUL_IDIOMATIC_EVM,
        description="Packing multiple sub-word variables (uint128, uint64, address) into a single 32-byte storage slot using bitwise shifts and masks.",
        recommendation="Group related state variables in single slots to save 20,000 gas per cold sstore.",
    ),
    PatternType.CUSTOM_ERROR_MEMORY_REVERT: PatternDefinition(
        type=PatternType.CUSTOM_ERROR_MEMORY_REVERT,
        name="Custom Error Memory Revert",
        category=PatternCategory.YUL_IDIOMATIC_EVM,
        description="Low-level custom error encoding in scratch space (mstore(0x00, selector), revert(0x1c, 0x24) / revert(0x00, 0x04)).",
        recommendation="Use 4-byte custom error selectors instead of long revert strings to minimize bytecode size and execution gas.",
    ),

    # 2. Low-Level Call Dispatch & Metaprogramming (4)
    PatternType.DELEGATECALL_FORWARDING_PROXY: PatternDefinition(
        type=PatternType.DELEGATECALL_FORWARDING_PROXY,
        name="Delegatecall Forwarding Proxy",
        category=PatternCategory.LOW_LEVEL_CALLS_METAPROGRAMMING,
        description="Assembly delegatecall forwarding pattern preserving caller context and copying returndata.",
        recommendation="Verify implementation address is not zero and validate caller authorization before delegatecall.",
    ),
    PatternType.DETERMINISTIC_CREATE2_DEPLOYER: PatternDefinition(
        type=PatternType.DETERMINISTIC_CREATE2_DEPLOYER,
        name="Deterministic CREATE2 Deployer",
        category=PatternCategory.LOW_LEVEL_CALLS_METAPROGRAMMING,
        description="On-chain deployment using create2 opcode with explicit salt and bytecode memory pointers.",
        recommendation="Check created address is non-zero to catch deployment reverts immediately.",
    ),
    PatternType.STATICCALL_VIEW_QUERY: PatternDefinition(
        type=PatternType.STATICCALL_VIEW_QUERY,
        name="Staticcall View Query",
        category=PatternCategory.LOW_LEVEL_CALLS_METAPROGRAMMING,
        description="Read-only external contract invocation using staticcall ensuring state immutability.",
        recommendation="Always check staticcall return status and copy returndata safely.",
    ),
    PatternType.CALLDATA_ZERO_COPY_STREAMING: PatternDefinition(
        type=PatternType.CALLDATA_ZERO_COPY_STREAMING,
        name="Calldata Zero-Copy Streaming",
        category=PatternCategory.LOW_LEVEL_CALLS_METAPROGRAMMING,
        description="Direct calldataload streaming loops bypassing memory allocation for high-throughput batch processing.",
        recommendation="Verify calldatasize bounds before loading offsets to prevent reading zero-padding as valid data.",
    ),

    # 3. Bitwise Arithmetic, Cryptography & Math (3)
    PatternType.BITWISE_MASKING_COMPRESSION: PatternDefinition(
        type=PatternType.BITWISE_MASKING_COMPRESSION,
        name="Bitwise Masking & Compression",
        category=PatternCategory.BITWISE_MATH_CRYPTO,
        description="Extracting or masking packed bitfields using and, or, xor, not, shl, shr operations.",
        recommendation="Clean dirty upper bits with explicit masks (and(val, 0xff...)) when converting between sizes.",
    ),
    PatternType.KECCAK256_HASH_SLOT_DERIVATION: PatternDefinition(
        type=PatternType.KECCAK256_HASH_SLOT_DERIVATION,
        name="Keccak256 Hash Slot Derivation",
        category=PatternCategory.BITWISE_MATH_CRYPTO,
        description="Calculating mapping storage slots or EIP-712 typed data hashes using keccak256(ptr, len).",
        recommendation="Use 0x00-0x3f scratch space for 64-byte keccak hashes without bumping the 0x40 free memory pointer.",
    ),
    PatternType.OVERFLOW_FREE_MODULO_ARITHMETIC: PatternDefinition(
        type=PatternType.OVERFLOW_FREE_MODULO_ARITHMETIC,
        name="Overflow-Free Modulo Arithmetic",
        category=PatternCategory.BITWISE_MATH_CRYPTO,
        description="Native EVM arbitrary-precision modulo operations using addmod and mulmod opcodes.",
        recommendation="Leverage addmod and mulmod for cryptography and modular math without intermediate 256-bit overflows.",
    ),

    # 4. Creational Patterns (5/5)
    PatternType.SINGLETON_STORAGE_SLOT_VAULT: PatternDefinition(
        type=PatternType.SINGLETON_STORAGE_SLOT_VAULT,
        name="Singleton Storage Slot Vault",
        category=PatternCategory.CREATIONAL,
        description="Singleton pattern managing global state at a deterministic keccak256 namespace storage slot.",
        recommendation="Adopt ERC-7201 diamond storage namespaces to eliminate slot collisions.",
    ),
    PatternType.FACTORY_CREATE2_INSTANCE_SPAWNER: PatternDefinition(
        type=PatternType.FACTORY_CREATE2_INSTANCE_SPAWNER,
        name="Factory CREATE2 Instance Spawner",
        category=PatternCategory.CREATIONAL,
        description="Factory pattern instantiating child contracts on-chain with deterministic addresses using create2.",
        recommendation="Emit creation events with the computed contract address for indexers.",
    ),
    PatternType.ABSTRACT_FACTORY_POOL_DISPATCHER: PatternDefinition(
        type=PatternType.ABSTRACT_FACTORY_POOL_DISPATCHER,
        name="Abstract Factory Pool Dispatcher",
        category=PatternCategory.CREATIONAL,
        description="Abstract factory creating liquidity pools or vault instances based on parameterized bytecode templates.",
        recommendation="Validate creation parameters before memory bytecode copying.",
    ),
    PatternType.BUILDER_MEMORY_CALLDATA_ENCODER: PatternDefinition(
        type=PatternType.BUILDER_MEMORY_CALLDATA_ENCODER,
        name="Builder Memory Calldata Encoder",
        category=PatternCategory.CREATIONAL,
        description="Builder pattern incrementally constructing structured ABI-encoded calldata in memory.",
        recommendation="Track byte offsets carefully to prevent overlapping memory buffers.",
    ),
    PatternType.PROTOTYPE_BYTECODE_CLONE_PACKER: PatternDefinition(
        type=PatternType.PROTOTYPE_BYTECODE_CLONE_PACKER,
        name="Prototype Bytecode Clone Packer",
        category=PatternCategory.CREATIONAL,
        description="Prototype pattern cloning contract bytecode via codecopy / extcodecopy for minimal proxies (ERC-1167).",
        recommendation="Use standardized EIP-1167 minimal proxy bytecode for minimal deployment gas.",
    ),

    # 5. Structural Patterns (7/7)
    PatternType.ADAPTER_INTERFACE_CALLDATA_REWRITER: PatternDefinition(
        type=PatternType.ADAPTER_INTERFACE_CALLDATA_REWRITER,
        name="Adapter Interface Calldata Rewriter",
        category=PatternCategory.STRUCTURAL,
        description="Adapter pattern transforming legacy or incompatible calldata payloads into canonical format.",
        recommendation="Validate incoming calldata length before slicing and restructuring.",
    ),
    PatternType.BRIDGE_CROSS_CONTRACT_RELAY: PatternDefinition(
        type=PatternType.BRIDGE_CROSS_CONTRACT_RELAY,
        name="Bridge Cross-Contract Relay",
        category=PatternCategory.STRUCTURAL,
        description="Bridge pattern decoupling external message dispatch from internal contract storage manipulation.",
        recommendation="Verify bridge message authenticity and prevent replay attacks with nonces.",
    ),
    PatternType.COMPOSITE_MULTICALL_BATCH: PatternDefinition(
        type=PatternType.COMPOSITE_MULTICALL_BATCH,
        name="Composite Multicall Batch",
        category=PatternCategory.STRUCTURAL,
        description="Composite pattern executing an array of heterogeneous contract calls in a single transaction loop.",
        recommendation="Implement bubbling of revert data when child calls fail.",
    ),
    PatternType.DECORATOR_MEMORY_PADDING_WRAPPER: PatternDefinition(
        type=PatternType.DECORATOR_MEMORY_PADDING_WRAPPER,
        name="Decorator Memory Padding Wrapper",
        category=PatternCategory.STRUCTURAL,
        description="Decorator pattern prepending length headers and padding byte buffers dynamically in memory.",
        recommendation="Ensure 32-byte word alignment for all ABI-encoded return buffers.",
    ),
    PatternType.FACADE_SELECTOR_ROUTER: PatternDefinition(
        type=PatternType.FACADE_SELECTOR_ROUTER,
        name="Facade Selector Router",
        category=PatternCategory.STRUCTURAL,
        description="Facade pattern routing external calls to internal helper subroutines via 4-byte selector jump tables.",
        recommendation="Provide a clean fallback handler for unmatched function selectors.",
    ),
    PatternType.FLYWEIGHT_IMMUTABLE_CODECOPY_SLOT: PatternDefinition(
        type=PatternType.FLYWEIGHT_IMMUTABLE_CODECOPY_SLOT,
        name="Flyweight Immutable Codecopy Slot",
        category=PatternCategory.STRUCTURAL,
        description="Flyweight pattern reading shared constants directly from deployed code via codecopy saving sload gas.",
        recommendation="Prefer codecopy over sload for configuration parameters that never change.",
    ),
    PatternType.PROXY_DELEGATECALL_FORWARDER: PatternDefinition(
        type=PatternType.PROXY_DELEGATECALL_FORWARDER,
        name="Proxy Delegatecall Forwarder",
        category=PatternCategory.STRUCTURAL,
        description="Transparent / UUPS / Diamond proxy forwarding calls via delegatecall and returning returndata.",
        recommendation="Use ERC-1967 standard storage slots for proxy implementation addresses.",
    ),

    # 6. Behavioral Patterns (11/11)
    PatternType.CHAIN_OF_RESPONSIBILITY_AUTH_FILTER: PatternDefinition(
        type=PatternType.CHAIN_OF_RESPONSIBILITY_AUTH_FILTER,
        name="Chain of Responsibility Auth Filter",
        category=PatternCategory.BEHAVIORAL,
        description="Sequenced validation checks (caller == owner, !paused, deadline >= block.timestamp) before execution.",
        recommendation="Fail fast at the earliest check to conserve execution gas.",
    ),
    PatternType.COMMAND_RAW_CALL_PAYLOAD: PatternDefinition(
        type=PatternType.COMMAND_RAW_CALL_PAYLOAD,
        name="Command Raw Call Payload",
        category=PatternCategory.BEHAVIORAL,
        description="Command pattern packaging { target, value, data_ptr, data_len } for delayed or multicall execution.",
        recommendation="Validate call target is not the contract itself unless self-calls are intentionally allowed.",
    ),
    PatternType.INTERPRETER_BYTECODE_EVALUATOR: PatternDefinition(
        type=PatternType.INTERPRETER_BYTECODE_EVALUATOR,
        name="Interpreter Bytecode Evaluator",
        category=PatternCategory.BEHAVIORAL,
        description="Interpreter pattern evaluating custom DSL instructions or order matching scripts in an assembly loop.",
        recommendation="Enforce bounded instruction count to prevent out-of-gas infinite loops.",
    ),
    PatternType.ITERATOR_CALLDATA_OFFSET_SCAN: PatternDefinition(
        type=PatternType.ITERATOR_CALLDATA_OFFSET_SCAN,
        name="Iterator Calldata Offset Scan",
        category=PatternCategory.BEHAVIORAL,
        description="Cursor-based iterator scanning packed calldata in 32-byte strides (add(offset, 0x20)).",
        recommendation="Ensure loop termination conditions strictly check calldatasize().",
    ),
    PatternType.MEDIATOR_ESCROW_ATOMIC_SWAP: PatternDefinition(
        type=PatternType.MEDIATOR_ESCROW_ATOMIC_SWAP,
        name="Mediator Escrow Atomic Swap",
        category=PatternCategory.BEHAVIORAL,
        description="Mediator pattern coordinating multi-token transfers atomically between trading counterparties.",
        recommendation="Verify transfer return values (or handle non-standard ERC-20 tokens that return no bool).",
    ),
    PatternType.MEMENTO_TRANSIENT_SLOT_CHECKPOINT: PatternDefinition(
        type=PatternType.MEMENTO_TRANSIENT_SLOT_CHECKPOINT,
        name="Memento Transient Slot Checkpoint",
        category=PatternCategory.BEHAVIORAL,
        description="Memento pattern snapshotting state into transient storage (tstore) and restoring on completion.",
        recommendation="Always reset transient checkpoints in a finally/cleanup block.",
    ),
    PatternType.OBSERVER_LOG_TOPIC_EMISSION: PatternDefinition(
        type=PatternType.OBSERVER_LOG_TOPIC_EMISSION,
        name="Observer Log Topic Emission",
        category=PatternCategory.BEHAVIORAL,
        description="Observer pattern emitting structured EVM logs (log1, log2, log3, log4) for off-chain indexers.",
        recommendation="Place indexed parameters in topics and unindexed parameters in the data memory slice.",
    ),
    PatternType.STATE_MACHINE_SLOT_LIFECYCLE: PatternDefinition(
        type=PatternType.STATE_MACHINE_SLOT_LIFECYCLE,
        name="State Machine Slot Lifecycle",
        category=PatternCategory.BEHAVIORAL,
        description="Finite State Machine tracking and transitioning lifecycle states (Uninitialized, Active, Paused, Killed).",
        recommendation="Enforce strict state transition guards to prevent jumping to illegal states.",
    ),
    PatternType.STRATEGY_JUMP_TABLE_INJECTION: PatternDefinition(
        type=PatternType.STRATEGY_JUMP_TABLE_INJECTION,
        name="Strategy Jump Table Injection",
        category=PatternCategory.BEHAVIORAL,
        description="Strategy pattern selecting algorithmic execution paths dynamically via switch or function pointers.",
        recommendation="Validate strategy indices to prevent undefined jump destinations.",
    ),
    PatternType.TEMPLATE_METHOD_HOOK_LIFECYCLE: PatternDefinition(
        type=PatternType.TEMPLATE_METHOD_HOOK_LIFECYCLE,
        name="Template Method Hook Lifecycle",
        category=PatternCategory.BEHAVIORAL,
        description="Fixed execution skeleton coordinating pre-execution checks, core call, and post-execution hooks.",
        recommendation="Keep core invariants enforced in the template method regardless of hook overrides.",
    ),
    PatternType.VISITOR_RETURN_DATA_RECEIVER: PatternDefinition(
        type=PatternType.VISITOR_RETURN_DATA_RECEIVER,
        name="Visitor Return Data Receiver",
        category=PatternCategory.BEHAVIORAL,
        description="Visitor pattern receiving, inspecting, and unpacking external call returndata via returndatacopy.",
        recommendation="Check returndatasize matches expected layout before unpacking fields.",
    ),

    # 7. Yul & EVM Assembly Security Hazards (4)
    PatternType.UNPROTECTED_DELEGATECALL_HAZARD: PatternDefinition(
        type=PatternType.UNPROTECTED_DELEGATECALL_HAZARD,
        name="Unprotected Delegatecall Hazard",
        category=PatternCategory.YUL_SECURITY_HAZARDS,
        description="delegatecall targeting user-supplied or unprotected address allowing complete storage takeover.",
        recommendation="Ensure delegatecall targets are strictly restricted to verified implementation addresses.",
    ),
    PatternType.UNBOUNDED_CALLDATA_LOOP_HAZARD: PatternDefinition(
        type=PatternType.UNBOUNDED_CALLDATA_LOOP_HAZARD,
        name="Unbounded Calldata Loop Hazard",
        category=PatternCategory.YUL_SECURITY_HAZARDS,
        description="Loop over calldata or memory without explicit upper bound check risking transaction out-of-gas failure.",
        recommendation="Enforce explicit maximum iteration limits or slice length validation.",
    ),
    PatternType.DIRTY_HIGHER_ORDER_BITS_HAZARD: PatternDefinition(
        type=PatternType.DIRTY_HIGHER_ORDER_BITS_HAZARD,
        name="Dirty Higher Order Bits Hazard",
        category=PatternCategory.YUL_SECURITY_HAZARDS,
        description="Using smaller integer or boolean types in assembly without masking dirty upper bits.",
        recommendation="Clean variables with and(val, 0xff...) or iszero(iszero(val)) before boolean comparisons.",
    ),
    PatternType.MEMORY_CORRUPTION_CLOBBER_HAZARD: PatternDefinition(
        type=PatternType.MEMORY_CORRUPTION_CLOBBER_HAZARD,
        name="Memory Corruption Clobber Hazard",
        category=PatternCategory.YUL_SECURITY_HAZARDS,
        description="Writing directly to memory without respecting or updating the 0x40 free memory pointer.",
        recommendation="Allocate memory starting from mload(0x40) and increment 0x40 accordingly.",
    ),

    # 8. SOLID Principles & Smells (3)
    PatternType.MONOLITHIC_YUL_OBJECT_SRP: PatternDefinition(
        type=PatternType.MONOLITHIC_YUL_OBJECT_SRP,
        name="Monolithic Yul Object SRP Violation",
        category=PatternCategory.PRINCIPLE,
        description="Yul object or assembly block defining excessive functions (>= 15), violating Single Responsibility.",
        recommendation="Decompose large assembly objects into focused helper sub-objects and libraries.",
    ),
    PatternType.FAT_MEMORY_STRUCT_ISP: PatternDefinition(
        type=PatternType.FAT_MEMORY_STRUCT_ISP,
        name="Fat Memory Struct ISP Violation",
        category=PatternCategory.PRINCIPLE,
        description="Memory buffer accessing excessive word offsets (>= 10 words), indicating an overly complex struct.",
        recommendation="Decompose large memory layouts into cohesive sub-structures.",
    ),
    PatternType.HARDCODED_STORAGE_SLOT_OCP: PatternDefinition(
        type=PatternType.HARDCODED_STORAGE_SLOT_OCP,
        name="Hardcoded Storage Slot OCP Smell",
        category=PatternCategory.PRINCIPLE,
        description="Magic literal storage slots (e.g. 0x0, 0x1) instead of keccak256-derived namespace hashes.",
        recommendation="Use ERC-7201 standard storage slot hashing (keccak256('protocol.storage...')) for clean upgrades.",
    ),
}
