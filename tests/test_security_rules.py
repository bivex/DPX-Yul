"""Unit tests for Yul & EVM Assembly security hazards."""

from __future__ import annotations

from pattern_detector.adapters.outbound.parsers.native_yul_parser import NativeYulParserAdapter
from pattern_detector.domain.rules.security_rules import (
    DirtyHigherOrderBitsHazardRule,
    MemoryCorruptionClobberHazardRule,
    UnboundedCalldataLoopHazardRule,
    UnprotectedDelegatecallHazardRule,
)
from pattern_detector.domain.value_objects import PatternType


def test_unprotected_delegatecall_hazard() -> None:
    code = """
function raw_delegate(target) {
    let success := delegatecall(gas(), target, 0, 0, 0, 0)
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("unsafe.yul", code)])

    rule = UnprotectedDelegatecallHazardRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.UNPROTECTED_DELEGATECALL_HAZARD


def test_unbounded_calldata_loop_hazard() -> None:
    code = """
function unsafe_loop() {
    for { let i := 0 } 1 { i := add(i, 32) } {
        let val := calldataload(i)
    }
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("unsafe.yul", code)])

    rule = UnboundedCalldataLoopHazardRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.UNBOUNDED_CALLDATA_LOOP_HAZARD


def test_dirty_higher_order_bits_hazard() -> None:
    code = """
function check_bool(b) -> res {
    // uint8 boolean without masking
    if eq(b, 1) {
        res := 1
    }
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("unsafe.yul", code)])

    rule = DirtyHigherOrderBitsHazardRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.DIRTY_HIGHER_ORDER_BITS_HAZARD


def test_memory_corruption_clobber_hazard() -> None:
    code = """
function corrupt_memory(val) {
    mstore(0x80, val)
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("unsafe.yul", code)])

    rule = MemoryCorruptionClobberHazardRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.MEMORY_CORRUPTION_CLOBBER_HAZARD
