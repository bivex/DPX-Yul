"""Code Model representation for Yul AST and EVM Inline Assembly structures."""

from __future__ import annotations

from dataclasses import dataclass, field
from pattern_detector.domain.value_objects import SourceLocation


@dataclass
class YulFunction:
    """Represents a Yul function (function foo(a, b) -> r { ... })."""

    name: str
    parameters: list[str] = field(default_factory=list)
    return_values: list[str] = field(default_factory=list)
    body: str = ""
    raw_text: str = ""
    location: SourceLocation | None = None
    has_mload_40: bool = False
    has_tstore: bool = False
    has_tload: bool = False
    has_delegatecall: bool = False
    has_staticcall: bool = False
    has_create2: bool = False
    has_revert: bool = False
    has_log: bool = False
    has_sload: bool = False
    has_sstore: bool = False
    has_keccak: bool = False
    has_codecopy: bool = False


@dataclass
class YulObject:
    """Represents a top-level or nested Yul Object (object "Contract" { code { ... } })."""

    name: str
    is_runtime: bool = False
    functions: list[YulFunction] = field(default_factory=list)
    raw_text: str = ""
    location: SourceLocation | None = None
    sub_objects: list[YulObject] = field(default_factory=list)

    @property
    def all_functions(self) -> list[YulFunction]:
        result = list(self.functions)
        for sub in self.sub_objects:
            result.extend(sub.all_functions)
        return result


@dataclass
class YulFile:
    """Represents a single Yul source file (.yul) or Solidity file containing assembly."""

    file_path: str
    raw_content: str
    lines: list[str] = field(default_factory=list)
    objects: list[YulObject] = field(default_factory=list)
    inline_assemblies: list[YulFunction] = field(default_factory=list)
    free_functions: list[YulFunction] = field(default_factory=list)

    @property
    def all_functions(self) -> list[YulFunction]:
        funcs = list(self.free_functions)
        funcs.extend(self.inline_assemblies)
        for obj in self.objects:
            funcs.extend(obj.all_functions)
        return funcs


@dataclass
class CodeModel:
    """Aggregated domain code model across all scanned Yul files."""

    target_path: str = ""
    files: list[YulFile] = field(default_factory=list)

    @property
    def all_objects(self) -> list[YulObject]:
        res: list[YulObject] = []
        for f in self.files:
            res.extend(f.objects)
        return res

    @property
    def all_functions(self) -> list[YulFunction]:
        res: list[YulFunction] = []
        for f in self.files:
            res.extend(f.all_functions)
        return res

    @property
    def all_assemblies(self) -> list[YulFunction]:
        res: list[YulFunction] = []
        for f in self.files:
            res.extend(f.inline_assemblies)
        return res
