"""Unit tests for Low-Level Call Dispatch & Metaprogramming rules in Yul."""

from __future__ import annotations

from pattern_detector.adapters.outbound.parsers.native_yul_parser import NativeYulParserAdapter
from pattern_detector.domain.rules.low_level_calls_rules import (
    CalldataZeroCopyStreamingRule,
    DelegatecallForwardingProxyRule,
    DeterministicCreate2DeployerRule,
    StaticcallViewQueryRule,
)
from pattern_detector.domain.value_objects import PatternType


def test_delegatecall_forwarding_proxy() -> None:
    code = """
function forward(target) {
    let success := delegatecall(gas(), target, 0, calldatasize(), 0, 0)
    returndatacopy(0, 0, returndatasize())
    switch success
    case 0 { revert(0, returndatasize()) }
    default { return(0, returndatasize()) }
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("proxy.yul", code)])

    rule = DelegatecallForwardingProxyRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.DELEGATECALL_FORWARDING_PROXY


def test_deterministic_create2_deployer() -> None:
    code = """
function deploy(salt, ptr, len) -> addr {
    addr := create2(0, ptr, len, salt)
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("deploy.yul", code)])

    rule = DeterministicCreate2DeployerRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.DETERMINISTIC_CREATE2_DEPLOYER


def test_staticcall_view_query() -> None:
    code = """
function query(target) {
    let ok := staticcall(gas(), target, 0, 4, 0, 32)
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("query.yul", code)])

    rule = StaticcallViewQueryRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.STATICCALL_VIEW_QUERY


def test_calldata_zero_copy_streaming() -> None:
    code = """
function stream_sum() -> sum {
    for { let i := 4 } lt(i, calldatasize()) { i := add(i, 32) } {
        sum := add(sum, calldataload(i))
    }
}
"""
    parser = NativeYulParserAdapter()
    model = parser.parse_codebase([("stream.yul", code)])

    rule = CalldataZeroCopyStreamingRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.CALLDATA_ZERO_COPY_STREAMING
