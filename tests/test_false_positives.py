"""Tests verifying zero false positives on clean, memory-safe Yul & EVM assembly code."""

from __future__ import annotations

from pattern_detector.adapters.outbound.parsers.native_yul_parser import NativeYulParserAdapter
from pattern_detector.domain.rules.security_rules import (
    MemoryCorruptionClobberHazardRule,
    UnprotectedDelegatecallHazardRule,
)
from pattern_detector.domain.rules.solid_principles_rules import MonolithicYulObjectSrpRule


def test_clean_safe_memory_allocation_no_hazard() -> None:
    code = """
function allocate_clean(size) -> ptr {
    ptr := mload(0x40)
    mstore(0x40, add(ptr, size))
    mstore(ptr, 123)
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("clean.yul", code)])

    rule = MemoryCorruptionClobberHazardRule()
    detections = rule.evaluate(model)

    assert len(detections) == 0


def test_clean_small_object_no_srp() -> None:
    code = """
object "Small" {
    code {
        function helper() {}
    }
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("clean.yul", code)])

    rule = MonolithicYulObjectSrpRule()
    detections = rule.evaluate(model)

    assert len(detections) == 0
