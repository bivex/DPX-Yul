"""Unit tests for CLI commands and JSON/Markdown/SARIF/HTML/LLM exporters for Yul."""

from __future__ import annotations

import json
from typer.testing import CliRunner

from pattern_detector.adapters.inbound.cli.main import app
from pattern_detector.adapters.outbound.persistence.formatters import (
    JsonReportFormatter,
    MarkdownReportFormatter,
    SarifReportFormatter,
)
from pattern_detector.adapters.outbound.persistence.html_report_formatter import HtmlReportFormatter
from pattern_detector.adapters.outbound.persistence.llm_report_formatter import LlmReportFormatter
from pattern_detector.domain.detection import Detection, DetectionReport
from pattern_detector.domain.value_objects import (
    Confidence,
    Evidence,
    PatternCategory,
    PatternType,
    SourceLocation,
)

runner = CliRunner()


def _dummy_report() -> DetectionReport:
    ev = Evidence(
        rule_code="YUL_TEST",
        description="Test heuristic for free memory pointer management",
        weight=0.95,
        location=SourceLocation("Vault.yul", 10),
    )
    det = Detection(
        pattern_type=PatternType.FREE_MEMORY_POINTER_MANAGEMENT,
        pattern_category=PatternCategory.YUL_IDIOMATIC_EVM,
        target_name="allocate",
        target_kind="function",
        confidence=Confidence(score=0.95, evidences=[ev]),
        primary_location=SourceLocation("Vault.yul", 10),
        evidences=[ev],
    )
    return DetectionReport(
        project_path="test_project",
        scanned_files_count=1,
        detections=[det],
        elapsed_seconds=0.012,
    )


def test_cli_rules_command() -> None:
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0
    assert "DPX-Yul" in result.stdout
    assert "YUL_IDIOMATIC_EVM" in result.stdout or "free_memory" in result.stdout


def test_cli_info_command() -> None:
    result = runner.invoke(app, ["info", "free_memory_pointer_management"])
    assert result.exit_code == 0
    assert "Free Memory Pointer Management" in result.stdout


def test_exporters_format() -> None:
    rep = _dummy_report()

    json_out = JsonReportFormatter().format(rep)
    data = json.loads(json_out)
    assert data["total_detections_count"] == 1

    md_out = MarkdownReportFormatter().format(rep)
    assert "# 🔥 DPX-Yul: Yul & EVM Assembly Architectural Pattern Report" in md_out

    sarif_out = SarifReportFormatter().format(rep)
    sarif_data = json.loads(sarif_out)
    assert sarif_data["version"] == "2.1.0"

    html_out = HtmlReportFormatter().format(rep)
    assert "DPX-Yul Architecture & EVM Assembly Observability HUD" in html_out

    llm_out = LlmReportFormatter().format_scan_report(rep)
    assert '<codebase_architecture_analysis language="yul">' in llm_out
