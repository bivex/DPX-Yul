"""Unit tests for Yul Idiomatic, EVM Memory & Storage Architecture rules."""

from __future__ import annotations

from pattern_detector.adapters.outbound.parsers.native_yul_parser import NativeYulParserAdapter
from pattern_detector.domain.rules.idiomatic_rules import (
    CustomErrorMemoryRevertRule,
    CustomFourbyteSelectorDispatcherRule,
    FreeMemoryPointerManagementRule,
    StorageSlotBitfieldPackingRule,
    TransientStorageEip1153Rule,
    YulObjectRuntimeHierarchyRule,
)
from pattern_detector.domain.value_objects import PatternType


def test_yul_object_runtime_hierarchy() -> None:
    code = """
object "Token" {
    code {
        datacopy(0, dataoffset("Token_deployed"), datasize("Token_deployed"))
        return(0, datasize("Token_deployed"))
    }
    object "Token_deployed" {
        code {
            return(0, 0)
        }
    }
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("Token.yul", code)])

    rule = YulObjectRuntimeHierarchyRule()
    detections = rule.evaluate(model)

    assert len(detections) >= 1
    assert any(d.pattern_type == PatternType.YUL_OBJECT_RUNTIME_HIERARCHY for d in detections)


def test_yul_object_runtime_variant() -> None:
    code = """
object "MyContract_runtime" {
    code {
        return(0, 0)
    }
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("Runtime.yul", code)])

    rule = YulObjectRuntimeHierarchyRule()
    detections = rule.evaluate(model)

    assert len(detections) >= 1


def test_inline_assembly_in_solidity() -> None:
    code = """
contract SoladyDemo {
    function testMem() external pure {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(0x40, add(ptr, 0x20))
        }
    }
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("SoladyDemo.sol", code)])

    rule = FreeMemoryPointerManagementRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.FREE_MEMORY_POINTER_MANAGEMENT


def test_free_memory_pointer_management() -> None:
    code = """
function allocate(size) -> ptr {
    ptr := mload(0x40)
    mstore(0x40, add(ptr, size))
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("alloc.yul", code)])

    rule = FreeMemoryPointerManagementRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.FREE_MEMORY_POINTER_MANAGEMENT


def test_transient_storage_eip1153() -> None:
    code = """
function lock() {
    if tload(0x0) { revert(0, 0) }
    tstore(0x0, 1)
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("lock.yul", code)])

    rule = TransientStorageEip1153Rule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.TRANSIENT_STORAGE_EIP1153


def test_custom_fourbyte_selector_dispatcher() -> None:
    code = """
function dispatch() {
    switch shr(224, calldataload(0))
    case 0xa9059cbb {
        // transfer
    }
    default {
        revert(0, 0)
    }
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("dispatch.yul", code)])

    rule = CustomFourbyteSelectorDispatcherRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.CUSTOM_FOURBYTE_SELECTOR_DISPATCHER


def test_storage_slot_bitfield_packing() -> None:
    code = """
function pack_and_store(slot, lower_val, upper_val) {
    let packed := or(lower_val, shl(128, upper_val))
    sstore(slot, packed)
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("pack.yul", code)])

    rule = StorageSlotBitfieldPackingRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.STORAGE_SLOT_BITFIELD_PACKING


def test_custom_error_memory_revert() -> None:
    code = """
function revert_custom() {
    mstore(0x00, 0xfb8f38b2)
    revert(0x1c, 0x24)
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("revert.yul", code)])

    rule = CustomErrorMemoryRevertRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.CUSTOM_ERROR_MEMORY_REVERT
