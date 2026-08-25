"""Unit tests for Bitwise Arithmetic, Cryptography & Math rules in Yul."""

from __future__ import annotations

from pattern_detector.adapters.outbound.parsers.native_yul_parser import NativeYulParserAdapter
from pattern_detector.domain.rules.bitwise_crypto_rules import (
    BitwiseMaskingCompressionRule,
    Keccak256HashSlotDerivationRule,
    OverflowFreeModuloArithmeticRule,
)
from pattern_detector.domain.value_objects import PatternType


def test_bitwise_masking_compression() -> None:
    code = """
function clean_address(val) -> addr {
    addr := and(val, 0xffffffffffffffffffffffffffffffffffffffff)
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("mask.yul", code)])

    rule = BitwiseMaskingCompressionRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.BITWISE_MASKING_COMPRESSION


def test_keccak256_hash_slot_derivation() -> None:
    code = """
function compute_slot(key, mapping_slot) -> slot {
    mstore(0x00, key)
    mstore(0x20, mapping_slot)
    slot := keccak256(0x00, 0x40)
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("keccak.yul", code)])

    rule = Keccak256HashSlotDerivationRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.KECCAK256_HASH_SLOT_DERIVATION


def test_overflow_free_modulo_arithmetic() -> None:
    code = """
function mod_math(a, b, m) -> res {
    res := addmod(a, b, m)
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("math.yul", code)])

    rule = OverflowFreeModuloArithmeticRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.OVERFLOW_FREE_MODULO_ARITHMETIC
