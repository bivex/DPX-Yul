"""Unit tests for Yul SOLID principles and code smells."""

from __future__ import annotations

from pattern_detector.adapters.outbound.parsers.native_yul_parser import NativeYulParserAdapter
from pattern_detector.domain.rules.solid_principles_rules import (
    FatMemoryStructIspRule,
    HardcodedStorageSlotOcpRule,
    MonolithicYulObjectSrpRule,
)
from pattern_detector.domain.value_objects import PatternType


def test_monolithic_yul_object_srp() -> None:
    funcs = "\n".join([f"        function fn_{i}() {{}}" for i in range(16)])
    code = f"""
object "Monolith" {{
    code {{
{funcs}
    }}
}}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("monolith.yul", code)])

    rule = MonolithicYulObjectSrpRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.MONOLITHIC_YUL_OBJECT_SRP


def test_fat_memory_struct_isp() -> None:
    stores = "\n".join([f"    mstore(add(ptr, {i * 32}), {i})" for i in range(11)])
    code = f"""
function fill_fat_struct(ptr) {{
{stores}
}}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("fat.yul", code)])

    rule = FatMemoryStructIspRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.FAT_MEMORY_STRUCT_ISP


def test_hardcoded_storage_slot_ocp() -> None:
    code = """
function set_admin(addr) {
    sstore(0, addr)
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("slot.yul", code)])

    rule = HardcodedStorageSlotOcpRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.HARDCODED_STORAGE_SLOT_OCP
