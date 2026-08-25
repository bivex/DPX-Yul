"""Unit tests for all 23 GoF Creational, Structural, and Behavioral patterns in Yul & EVM Assembly."""

from __future__ import annotations

from pattern_detector.adapters.outbound.parsers.native_yul_parser import NativeYulParserAdapter
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
from pattern_detector.domain.rules.creational_rules import (
    AbstractFactoryPoolDispatcherRule,
    BuilderMemoryCalldataEncoderRule,
    FactoryCreate2InstanceSpawnerRule,
    PrototypeBytecodeClonePackerRule,
    SingletonStorageSlotVaultRule,
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
from pattern_detector.domain.value_objects import PatternType


# --- Creational (5/5) ---

def test_singleton_storage_slot_vault() -> None:
    code = """
function get_vault_state() -> val {
    val := sload(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc)
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("vault.yul", code)])

    rule = SingletonStorageSlotVaultRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.SINGLETON_STORAGE_SLOT_VAULT


def test_factory_create2_instance_spawner() -> None:
    code = """
function spawn_child(salt, ptr, len) -> addr {
    addr := create2(0, ptr, len, salt)
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("factory.yul", code)])

    rule = FactoryCreate2InstanceSpawnerRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.FACTORY_CREATE2_INSTANCE_SPAWNER


def test_abstract_factory_pool_dispatcher() -> None:
    code = """
function create_pool(token_a, token_b) {
    let addr := create2(0, 0, 32, 0)
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("pool.yul", code)])

    rule = AbstractFactoryPoolDispatcherRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.ABSTRACT_FACTORY_POOL_DISPATCHER


def test_builder_memory_calldata_encoder() -> None:
    code = """
function build_calldata_payload(ptr, a, b) {
    mstore(add(ptr, 0x00), a)
    mstore(add(ptr, 0x20), b)
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("builder.yul", code)])

    rule = BuilderMemoryCalldataEncoderRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.BUILDER_MEMORY_CALLDATA_ENCODER


def test_prototype_bytecode_clone_packer() -> None:
    code = """
function clone_proxy(target) {
    codecopy(0, 0, 32)
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("clone.yul", code)])

    rule = PrototypeBytecodeClonePackerRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.PROTOTYPE_BYTECODE_CLONE_PACKER


# --- Structural (7/7) ---

def test_adapter_interface_calldata_rewriter() -> None:
    code = """
function adapt_calldata(src_ptr, dst_ptr) {
    calldatacopy(dst_ptr, src_ptr, 64)
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("adapter.yul", code)])

    rule = AdapterInterfaceCalldataRewriterRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.ADAPTER_INTERFACE_CALLDATA_REWRITER


def test_bridge_cross_contract_relay() -> None:
    code = """
function bridge_relay(target, val) {
    let ok := call(gas(), target, val, 0, 0, 0, 0)
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("bridge.yul", code)])

    rule = BridgeCrossContractRelayRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.BRIDGE_CROSS_CONTRACT_RELAY


def test_composite_multicall_batch() -> None:
    code = """
function multicall_batch(count) {
    for { let i := 0 } lt(i, count) { i := add(i, 1) } {
        let ok := call(gas(), 0, 0, 0, 0, 0, 0)
    }
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("composite.yul", code)])

    rule = CompositeMulticallBatchRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.COMPOSITE_MULTICALL_BATCH


def test_decorator_memory_padding_wrapper() -> None:
    code = """
function pad_memory_buffer(ptr, len) {
    mstore(ptr, len)
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("decorator.yul", code)])

    rule = DecoratorMemoryPaddingWrapperRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.DECORATOR_MEMORY_PADDING_WRAPPER


def test_facade_selector_router() -> None:
    code = """
function route_selector() {
    switch calldataload(0)
    case 0x12345678 { return(0, 0) }
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("facade.yul", code)])

    rule = FacadeSelectorRouterRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.FACADE_SELECTOR_ROUTER


def test_flyweight_immutable_codecopy_slot() -> None:
    code = """
function get_immutable_token() -> t {
    codecopy(0, 0x100, 32)
    t := mload(0)
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("flyweight.yul", code)])

    rule = FlyweightImmutableCodecopySlotRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.FLYWEIGHT_IMMUTABLE_CODECOPY_SLOT


def test_proxy_delegatecall_forwarder() -> None:
    code = """
function proxy_forward(target) {
    let ok := delegatecall(gas(), target, 0, calldatasize(), 0, 0)
    returndatacopy(0, 0, returndatasize())
    return(0, returndatasize())
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("proxy.yul", code)])

    rule = ProxyDelegatecallForwarderRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.PROXY_DELEGATECALL_FORWARDER


# --- Behavioral (11/11) ---

def test_chain_of_responsibility_auth_filter() -> None:
    code = """
function check_require_auth(owner) {
    if iszero(eq(caller(), owner)) {
        revert(0, 0)
    }
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("auth.yul", code)])

    rule = ChainOfResponsibilityAuthFilterRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.CHAIN_OF_RESPONSIBILITY_AUTH_FILTER


def test_command_raw_call_payload() -> None:
    code = """
function execute_call_command(target, val, ptr, len) {
    let ok := call(gas(), target, val, ptr, len, 0, 0)
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("command.yul", code)])

    rule = CommandRawCallPayloadRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.COMMAND_RAW_CALL_PAYLOAD


def test_interpreter_bytecode_evaluator() -> None:
    code = """
function eval_interpreter_loop(pc) {
    switch pc
    case 0x01 { return(0, 0) }
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("eval.yul", code)])

    rule = InterpreterBytecodeEvaluatorRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.INTERPRETER_BYTECODE_EVALUATOR


def test_iterator_calldata_offset_scan() -> None:
    code = """
function scan_offsets() {
    for { let offset := 0 } lt(offset, 128) { offset := add(offset, 0x20) } {
        let val := calldataload(offset)
    }
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("scan.yul", code)])

    rule = IteratorCalldataOffsetScanRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.ITERATOR_CALLDATA_OFFSET_SCAN


def test_mediator_escrow_atomic_swap() -> None:
    code = """
function escrow_swap_settle(token, a, b) {
    // transfer tokens
    let ok := call(gas(), token, 0, 0, 0, 0, 0)
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("escrow.yul", code)])

    rule = MediatorEscrowAtomicSwapRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.MEDIATOR_ESCROW_ATOMIC_SWAP


def test_memento_transient_slot_checkpoint() -> None:
    code = """
function lock_transient_checkpoint(slot) {
    let old := tload(slot)
    tstore(slot, 1)
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("memento.yul", code)])

    rule = MementoTransientSlotCheckpointRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.MEMENTO_TRANSIENT_SLOT_CHECKPOINT


def test_observer_log_topic_emission() -> None:
    code = """
function emit_transfer_log(from, to, val) {
    mstore(0x00, val)
    log3(0x00, 0x20, 0xddf252ad1be2c89b69c2b068fc378d579fb83fbf, from, to)
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("log.yul", code)])

    rule = ObserverLogTopicEmissionRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.OBSERVER_LOG_TOPIC_EMISSION


def test_state_machine_slot_lifecycle() -> None:
    code = """
function advance_state_phase(slot, new_state) {
    let cur := sload(slot)
    sstore(slot, new_state)
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("state.yul", code)])

    rule = StateMachineSlotLifecycleRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.STATE_MACHINE_SLOT_LIFECYCLE


def test_strategy_jump_table_injection() -> None:
    code = """
function strategy_mode_calc(mode, a, b) -> res {
    switch mode
    case 0 { res := add(a, b) }
    case 1 { res := mul(a, b) }
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("strategy.yul", code)])

    rule = StrategyJumpTableInjectionRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.STRATEGY_JUMP_TABLE_INJECTION


def test_template_method_hook_lifecycle() -> None:
    code = """
function execute_with_hooks(target) {
    let pre := before_call()
    let ok := call(gas(), target, 0, 0, 0, 0, 0)
    let post := after_call()
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("template.yul", code)])

    rule = TemplateMethodHookLifecycleRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.TEMPLATE_METHOD_HOOK_LIFECYCLE


def test_visitor_return_data_receiver() -> None:
    code = """
function unpack_return_data() {
    let size := returndatasize()
    returndatacopy(0, 0, size)
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("visitor.yul", code)])

    rule = VisitorReturnDataReceiverRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.VISITOR_RETURN_DATA_RECEIVER
