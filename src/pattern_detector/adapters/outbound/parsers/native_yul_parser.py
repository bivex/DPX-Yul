"""High-speed native parser adapter for Yul objects (.yul) and EVM inline assembly blocks."""

from __future__ import annotations

import re
from pattern_detector.domain.code_model import CodeModel, YulFile, YulFunction, YulObject
from pattern_detector.domain.value_objects import SourceLocation
from pattern_detector.ports.outbound import ParserPort


def _extract_opcodes(body: str, func: YulFunction) -> None:
    """Extract known EVM opcodes and features from Yul function body."""
    func.has_mload_40 = "mload(0x40)" in body or "mload( 0x40" in body
    func.has_tstore = "tstore(" in body
    func.has_tload = "tload(" in body
    func.has_delegatecall = "delegatecall(" in body
    func.has_staticcall = "staticcall(" in body
    func.has_create2 = "create2(" in body
    func.has_revert = "revert(" in body
    func.has_log = any(f"log{i}(" in body for i in range(5))
    func.has_sload = "sload(" in body
    func.has_sstore = "sstore(" in body
    func.has_keccak = "keccak256(" in body
    func.has_codecopy = "codecopy(" in body or "extcodecopy(" in body


class NativeYulParserAdapter(ParserPort):
    """Single-pass robust parser extracting Yul objects, functions, and inline assembly blocks."""

    OBJECT_PATTERN = re.compile(r'^\s*object\s+"(?P<name>[^"]+)"\s*\{')
    FUNCTION_PATTERN = re.compile(
        r"^\s*function\s+(?P<name>[a-zA-Z0-9_$]+)\s*\((?P<params>[^)]*)\)(?:\s*->\s*(?P<returns>[^{]+))?\s*\{"
    )
    ASSEMBLY_BLOCK_PATTERN = re.compile(r"^\s*assembly\s*(?:\([^)]*\))?\s*\{")

    def parse_file(self, file_path: str, content: str) -> YulFile:
        lines = content.splitlines()
        file_obj = YulFile(file_path=file_path, raw_content=content, lines=lines)

        current_object_stack: list[tuple[YulObject, int]] = []
        current_function: YulFunction | None = None
        func_brace_depth = 0
        func_body_lines: list[str] = []

        current_assembly: YulFunction | None = None
        asm_brace_depth = 0
        asm_body_lines: list[str] = []

        for line_idx, raw_line in enumerate(lines, 1):
            trimmed = raw_line.strip()

            if trimmed.startswith("//") or not trimmed or trimmed.startswith("/*"):
                continue

            # Check for object declaration
            obj_m = self.OBJECT_PATTERN.match(trimmed)
            if obj_m:
                o_name = obj_m.group("name")
                is_runtime = "_deployed" in o_name.lower() or "runtime" in o_name.lower()
                y_obj = YulObject(
                    name=o_name,
                    is_runtime=is_runtime,
                    raw_text=raw_line,
                    location=SourceLocation(file_path=file_path, line=line_idx, column=1),
                )
                if current_object_stack:
                    parent_obj, _ = current_object_stack[-1]
                    parent_obj.sub_objects.append(y_obj)
                else:
                    file_obj.objects.append(y_obj)

                brace_delta = raw_line.count("{") - raw_line.count("}")
                current_object_stack.append((y_obj, brace_delta))
                continue

            # If inside object stack, track braces
            if current_object_stack and not current_function:
                # Update top object depth
                top_obj, depth = current_object_stack[-1]
                depth += raw_line.count("{") - raw_line.count("}")
                if depth <= 0:
                    current_object_stack.pop()
                else:
                    current_object_stack[-1] = (top_obj, depth)

            # Check for inline assembly block in Solidity
            if not current_assembly and not current_function:
                asm_m = self.ASSEMBLY_BLOCK_PATTERN.match(trimmed)
                if asm_m:
                    current_assembly = YulFunction(
                        name=f"inline_assembly_L{line_idx}",
                        location=SourceLocation(file_path=file_path, line=line_idx, column=1),
                        raw_text=raw_line,
                    )
                    asm_body_lines = [raw_line]
                    asm_brace_depth = raw_line.count("{") - raw_line.count("}")
                    if asm_brace_depth <= 0 and "{" in raw_line and "}" in raw_line:
                        current_assembly.body = "\n".join(asm_body_lines)
                        _extract_opcodes(current_assembly.body, current_assembly)
                        file_obj.inline_assemblies.append(current_assembly)
                        current_assembly = None
                        asm_body_lines = []
                        asm_brace_depth = 0
                    continue

            if current_assembly and not current_function:
                asm_body_lines.append(raw_line)
                asm_brace_depth += raw_line.count("{") - raw_line.count("}")

                # Also check if there are sub-functions declared inside assembly block
                fn_m = self.FUNCTION_PATTERN.match(trimmed)
                if fn_m:
                    f_name = fn_m.group("name")
                    params_str = fn_m.group("params") or ""
                    params = [p.strip() for p in params_str.split(",") if p.strip()]
                    returns_str = fn_m.group("returns") or ""
                    returns = [r.strip() for r in returns_str.split(",") if r.strip()]

                    current_function = YulFunction(
                        name=f_name,
                        parameters=params,
                        return_values=returns,
                        location=SourceLocation(file_path=file_path, line=line_idx, column=1),
                        raw_text=raw_line,
                    )
                    func_body_lines = [raw_line]
                    func_brace_depth = raw_line.count("{") - raw_line.count("}")
                    continue

                if asm_brace_depth <= 0:
                    current_assembly.body = "\n".join(asm_body_lines)
                    _extract_opcodes(current_assembly.body, current_assembly)
                    file_obj.inline_assemblies.append(current_assembly)
                    current_assembly = None
                    asm_body_lines = []
                    asm_brace_depth = 0
                continue

            # Check for function definition inside or outside object/assembly
            if not current_function:
                fn_m = self.FUNCTION_PATTERN.match(trimmed)
                if fn_m:
                    f_name = fn_m.group("name")
                    params_str = fn_m.group("params") or ""
                    params = [p.strip() for p in params_str.split(",") if p.strip()]
                    returns_str = fn_m.group("returns") or ""
                    returns = [r.strip() for r in returns_str.split(",") if r.strip()]

                    current_function = YulFunction(
                        name=f_name,
                        parameters=params,
                        return_values=returns,
                        location=SourceLocation(file_path=file_path, line=line_idx, column=1),
                        raw_text=raw_line,
                    )
                    func_body_lines = [raw_line]
                    func_brace_depth = raw_line.count("{") - raw_line.count("}")
                    if func_brace_depth <= 0 and "{" in raw_line and "}" in raw_line:
                        current_function.body = "\n".join(func_body_lines)
                        _extract_opcodes(current_function.body, current_function)
                        if current_object_stack:
                            current_object_stack[-1][0].functions.append(current_function)
                        else:
                            file_obj.free_functions.append(current_function)
                        current_function = None
                        func_body_lines = []
                        func_brace_depth = 0
                    continue

            if current_function:
                func_body_lines.append(raw_line)
                func_brace_depth += raw_line.count("{") - raw_line.count("}")
                if func_brace_depth <= 0:
                    current_function.body = "\n".join(func_body_lines)
                    _extract_opcodes(current_function.body, current_function)
                    if current_object_stack:
                        current_object_stack[-1][0].functions.append(current_function)
                    else:
                        file_obj.free_functions.append(current_function)
                    current_function = None
                    func_body_lines = []
                    func_brace_depth = 0
                continue

        return file_obj

    def parse_codebase(self, files: list[tuple[str, str]], target_path: str = "") -> CodeModel:
        model = CodeModel(target_path=target_path)
        for fpath, content in files:
            y_file = self.parse_file(fpath, content)
            model.files.append(y_file)
        return model
