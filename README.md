# 🔥 DPX-Yul: EVM Memory Layouts, Storage Packing, Transient Storage (EIP-1153) & GoF 23 Static Analyzer

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Yul Version](https://img.shields.io/badge/Yul-0.8.x%20--%200.8.28+%20%7C%20Cancun%20EIP--1153-f5841f?logo=ethereum&logoColor=white)](https://docs.soliditylang.org/en/latest/yul.html)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://python.org)
[![Architecture: Hexagonal DDD](https://img.shields.io/badge/Architecture-Hexagonal%20DDD-blueviolet)](https://alistair.cockburn.us/hexagonal-architecture/)
[![CLI: Typer & Rich](https://img.shields.io/badge/CLI-Typer%20%26%20Rich-009688)](https://typer.tiangolo.com)
[![SARIF OASIS v2.1.0](https://img.shields.io/badge/SARIF-OASIS%20v2.1.0-blue)](https://sarifweb.azurewebsites.net)

**DPX-Yul** is an enterprise-grade static analysis engine and architectural pattern detector for **Yul standalone objects (`.yul`)** and **EVM Inline Assembly (`assembly { ... }`)**. Engineered for **EVM Memory Management (`0x40` free memory pointer), Storage Slot Bitfield Packing (`sload`/`sstore`), Transient Storage (`tstore`/`tload` EIP-1153), Custom 4-Byte Selector Jump Tables, Low-Level Metaprogramming (`delegatecall`, `create2`, `staticcall`), Custom Error Memory Reverts (`revert(0x1c, 0x24)`), all 23 GoF Design Patterns**, and **EVM Assembly Security Hazards (Unprotected Delegatecalls, Unbounded Calldata Loops, Dirty Higher-Order Bits, Memory Clobbering)**.

[Features](#-key-features) • [Installation](#-installation) • [CLI Usage](#-cli-usage) • [Supported Rules](#-supported-pattern-rules--checks) • [The DPX Suite Family](#-the-dpx-suite-family)

</div>

---

## 🌟 Key Features

- 🧠 **EVM Memory & Pointer Management:** Audits free memory pointer manipulation (`mload(0x40)`, `mstore(0x40, add(ptr, size))`) and detects memory corruption risks.
- ⚡ **Transient Storage (EIP-1153):** Audits temporary transaction-scoped storage opcodes (`tstore`, `tload`) for reentrancy locks and transient contexts.
- 🗄️ **Storage Slot Bitfield Packing:** Identifies sub-word bitfield packing (`shr`, `shl`, `and`, `or`, `sstore`) saving cold storage gas.
- 🔀 **Low-Level Call Dispatch & Proxies:** Audits raw EVM message passing (`delegatecall`, `create2`, `staticcall`, `returndatacopy`).
- 🛑 **Custom Error Memory Reverts:** Analyzes scratch space error encoding (`mstore(0x00, selector)`, `revert(0x1c, 0x24)`).
- 🏛️ **100% Complete Gang of Four (GoF 23/23):** Full coverage of all 23 Creational, Structural, and Behavioral design patterns tailored for EVM assembly and Yul.
- 🛡️ **EVM Assembly Security Hazards:** Flags unprotected delegatecalls, unbounded calldata loops, unmasked dirty higher-order bits, and memory clobbering.
- 📊 **Interactive Architecture Observability HUD:** Zero-dependency interactive HTML dashboard with instant search, KPI breakdown, and built-in **`🤖 Copy AI Context Prompt`** generator for LLMs (Claude, GPT-4, Gemini).
- 🔒 **CI/CD & GitHub Security Ready:** Standardized **OASIS SARIF v2.1.0**, JSON, and Markdown reports.

---

## 📦 Installation

```bash
# Clone repository
git clone https://github.com/bivex/DPX-Yul.git
cd DPX-Yul

# Install dependencies using uv or pip
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

---

## 💻 CLI Usage

### 1. Scan a Yul / Solidity Assembly Codebase
```bash
# Terminal scan with Rich formatting
dpx-yul scan /path/to/yul/package

# Export Interactive HTML Observability HUD
dpx-yul scan contracts/ -H reports/yul_hud.html

# Generate AI Context Prompt for LLMs
dpx-yul scan contracts/ --llm

# Filter for Transient Storage or Free Memory Pointer rules
dpx-yul scan contracts/ -p transient_storage_eip1153 -p free_memory_pointer_management

# Export SARIF for GitHub Code Scanning
dpx-yul scan contracts/ -S reports/results.sarif
```

### 2. Inspect Supported Architectural Rules
```bash
dpx-yul rules
```

### 3. Query Deep Pattern Documentation
```bash
dpx-yul info free_memory_pointer_management
dpx-yul info transient_storage_eip1153
```

---

## 📋 Supported Pattern Rules & Checks

### 1. 🔥 Yul Idiomatic, EVM Memory & Storage Architecture
- `yul_object_runtime_hierarchy`: Nested Yul object declaring constructor init code and deployed runtime object (`object "Contract_deployed"`).
- `free_memory_pointer_management`: Standard EVM memory allocation loading and updating the 0x40 free memory pointer (`mload(0x40)`, `mstore(0x40, ...)`).
- `transient_storage_eip1153`: Temporary transaction-scoped storage utilizing `tstore` and `tload` opcodes for gas-efficient reentrancy locks.
- `custom_fourbyte_selector_dispatcher`: Direct calldata extraction of function selector (`shr(224, calldataload(0))`) with optimized switch-case branching.
- `storage_slot_bitfield_packing`: Packing multiple sub-word variables into a single 32-byte storage slot using bitwise shifts and masks.
- `custom_error_memory_revert`: Low-level custom error encoding in scratch space (`mstore(0x00, selector)`, `revert(0x1c, 0x24)`).

### 2. ⚡ Low-Level Call Dispatch & Metaprogramming
- `delegatecall_forwarding_proxy`: Assembly delegatecall forwarding pattern preserving caller context and copying returndata.
- `deterministic_create2_deployer`: On-chain deployment using `create2` opcode with explicit salt and bytecode memory pointers.
- `staticcall_view_query`: Read-only external contract invocation using `staticcall` ensuring state immutability.
- `calldata_zero_copy_streaming`: Direct `calldataload` streaming loops bypassing memory allocation for high-throughput batch processing.

### 3. 📐 Bitwise Arithmetic, Cryptography & Math
- `bitwise_masking_compression`: Extracting or masking packed bitfields using bitwise operations (`and`, `or`, `shl`, `shr`).
- `keccak256_hash_slot_derivation`: Calculating mapping storage slots or EIP-712 typed data hashes using `keccak256(ptr, len)`.
- `overflow_free_modulo_arithmetic`: Native EVM arbitrary-precision modulo operations using `addmod` and `mulmod` opcodes.

### 4. 🏛️ GoF Creational Patterns (5/5)
- `singleton_storage_slot_vault`: Singleton pattern managing global state at a deterministic keccak256 namespace storage slot.
- `factory_create2_instance_spawner`: Factory pattern instantiating child contracts on-chain with deterministic addresses using `create2`.
- `abstract_factory_pool_dispatcher`: Abstract factory creating liquidity pools or vault instances based on parameterized bytecode templates.
- `builder_memory_calldata_encoder`: Builder pattern incrementally constructing structured ABI-encoded calldata in memory.
- `prototype_bytecode_clone_packer`: Prototype pattern cloning contract bytecode via `codecopy` / `extcodecopy` for minimal proxies (EIP-1167).

### 5. 🧱 GoF Structural Patterns (7/7)
- `adapter_interface_calldata_rewriter`: Adapter pattern transforming legacy or incompatible calldata payloads into canonical format.
- `bridge_cross_contract_relay`: Bridge pattern decoupling external message dispatch from internal contract storage manipulation.
- `composite_multicall_batch`: Composite pattern executing an array of heterogeneous contract calls in a single transaction loop.
- `decorator_memory_padding_wrapper`: Decorator pattern prepending length headers and padding byte buffers dynamically in memory.
- `facade_selector_router`: Facade pattern routing external calls to internal helper subroutines via 4-byte selector jump tables.
- `flyweight_immutable_codecopy_slot`: Flyweight pattern reading shared constants directly from deployed code via `codecopy` saving `sload` gas.
- `proxy_delegatecall_forwarder`: Transparent / UUPS / Diamond proxy forwarding calls via `delegatecall` and returning returndata.

### 6. 🎯 GoF Behavioral Patterns (11/11)
- `chain_of_responsibility_auth_filter`: Sequenced validation checks in assembly (`caller == owner`, `!paused`, `deadline >= timestamp`).
- `command_raw_call_payload`: Command pattern packaging `{ target, value, data_ptr, data_len }` for delayed or multicall execution.
- `interpreter_bytecode_evaluator`: Interpreter pattern evaluating custom DSL instructions or order matching scripts in an assembly loop.
- `iterator_calldata_offset_scan`: Cursor-based iterator scanning packed calldata in 32-byte strides (`add(offset, 0x20)`).
- `mediator_escrow_atomic_swap`: Mediator pattern coordinating multi-token transfers atomically between trading counterparties.
- `memento_transient_slot_checkpoint`: Memento pattern snapshotting state into transient storage (`tstore`) and restoring on completion.
- `observer_log_topic_emission`: Observer pattern emitting structured EVM logs (`log1`, `log2`, `log3`, `log4`) for off-chain indexers.
- `state_machine_slot_lifecycle`: Finite State Machine tracking and transitioning lifecycle states stored in storage slots.
- `strategy_jump_table_injection`: Strategy pattern selecting algorithmic execution paths dynamically via switch or function pointers.
- `template_method_hook_lifecycle`: Fixed execution skeleton coordinating pre-execution checks, core call, and post-execution hooks.
- `visitor_return_data_receiver`: Visitor pattern receiving, inspecting, and unpacking external call returndata via `returndatacopy`.

### 7. 🛡️ Yul & EVM Assembly Security Hazards
- `unprotected_delegatecall_hazard`: `delegatecall` targeting user-supplied or unprotected address allowing complete storage takeover.
- `unbounded_calldata_loop_hazard`: Loop over calldata or memory without explicit upper bound check risking transaction out-of-gas failure.
- `dirty_higher_order_bits_hazard`: Using smaller integer or boolean types in assembly without masking dirty upper bits.
- `memory_corruption_clobber_hazard`: Writing directly to memory without respecting or updating the `0x40` free memory pointer.

### 8. 📐 SOLID Principles & Smells
- `monolithic_yul_object_srp`: Yul object or assembly block defining excessive functions (>= 15), violating Single Responsibility.
- `fat_memory_struct_isp`: Memory buffer accessing excessive word offsets (>= 10 words), indicating an overly complex struct.
- `hardcoded_storage_slot_ocp`: Magic literal storage slots (e.g. `0x0`, `0x1`) instead of keccak256-derived namespace hashes.

---

## 🌐 The DPX Suite Family

Cross-language architectural static analysis across all modern programming languages:

| Repository | Language / Ecosystem | Primary Paradigms & Focus |
|---|---|---|
| **[`DPX-Huff`](https://github.com/bivex/DPX-Huff)** | **Huff / EVM Stack Assembly** (0.3.x+ / Cancun) | **Macros, Stack Layout, Jumpdest Labels, Selector Dispatchers, GoF 23** |
| **[`DPX-Yul`](https://github.com/bivex/DPX-Yul)** | **Yul / EVM Assembly** (0.8.x - 0.8.28+ / Cancun) | **Memory Management, Storage Packing, Transient Storage (EIP-1153), GoF 23** |
| **[`DPX-Cairo`](https://github.com/bivex/DPX-Cairo)** | **Cairo** (Cairo 1.0 - 2.8+ / Starknet) | **Components, Storage Mapping, Syscalls, Account Abstraction, Upgrades, GoF 23** |
| **[`DPX-Move`](https://github.com/bivex/DPX-Move)** | **Move** (Move 2024 / Aptos / Sui) | **Linear Resources, Abilities, Sui Objects, Hot Potato, Prover, GoF 23** |
| **[`DPX-Lua`](https://github.com/bivex/DPX-Lua)** | **Lua / Luau** (5.1 - 5.4 / LuaJIT) | **Metatable OOP, Coroutines, LuaJIT FFI, GameDev (Roblox/Neovim), GoF 23** |
| **[`DPX-Solidity`](https://github.com/bivex/DPX-Solidity)** | **Solidity** (0.8.x - 0.8.28+) | **EVM Gas Optimization, Proxies, CEI Reentrancy, Yul, GoF 23, Security** |
| **[`DPX-Zig`](https://github.com/bivex/DPX-Zig)** | **Zig** (0.11 - 0.14+) | **Comptime Generics, Allocator RAII, Defer Cleanup, SIMD, GoF 23** |
| **[`DPX-Gleam`](https://github.com/bivex/DPX-Gleam)** | **Gleam** (1.0 - 1.8+) | **Type-Safe OTP Actors, Algebraic Data Types, Railway Monads, GoF 23** |
| **[`DPX-Mojo`](https://github.com/bivex/DPX-Mojo)** | **Mojo** (24.x - 25.x+) | **SIMD Vectorization, Ownership, Memory Safety, GoF 23, AI Acceleration** |
| **[`DPX-Julia`](https://github.com/bivex/DPX-Julia)** | **Julia** (1.6 - 1.11+) | **Multiple Dispatch, Holy Traits, Metaprogramming, Tasks, GoF 23** |
| **[`DPX-Kotlin`](https://github.com/bivex/DPX-Kotlin)** | **Kotlin** (1.8 - 2.0+) | **Coroutines, Flow, Jetpack Compose, Multiplatform, GoF 23** |
| **[`DPX-Swift`](https://github.com/bivex/DPX-Swift)** | **Swift** (5.5 - 6.0+) | **Protocol-Oriented, Actor Concurrency, SwiftUI, ARC Safety** |
| **[`DPX-CSharp`](https://github.com/bivex/DPX-CSharp)** | **C#** (10 - 13 / .NET 8-9) | **Clean Architecture, CQRS MediatR, Channel Pipelines** |
| **[`DPX-TypeScript`](https://github.com/bivex/DPX-TypeScript)** | **TypeScript / JavaScript** | **Hexagonal DI, Decorator Meta, Reactive Streams, React/NestJS** |
| **[`DPX-Rust`](https://github.com/bivex/DPX-Rust)** | **Rust** (Edition 2021/2024) | **Zero-Cost Abstractions, RAII Lifetimes, Typestate Pattern** |
| **[`DPX-Go`](https://github.com/bivex/DPX-Go)** | **Go** (1.18 - 1.24+) | **Goroutine Channels, CSP Concurrency, Pipeline Streaming** |
| **[`DPX-Py`](https://github.com/bivex/DPX-Py)** | **Python** (3.8 - 3.13+) | **Multi-Paradigm Hexagonal, Data Flow Engine, AsyncIO** |
| **[`DPX-Php`](https://github.com/bivex/DPX-Php)** | **PHP** (8.1 - 8.4+) | **Attribute-driven DDD, Fiber Concurrency, Laravel/Symfony** |
| **[`DPX-Haskell`](https://github.com/bivex/DPX-Haskell)** | **Haskell** (GHC 9.2 - 9.12+) | **Category Theory, Monad Transformers, Free Monads, Optics** |
| **[`DPX-OCaml`](https://github.com/bivex/DPX-OCaml)** | **OCaml** (4.14 - 5.3+ Multicore) | **Functor Modules, Effect Handlers, GADTs, Railway Monads** |
| **[`DPX-Elixir`](https://github.com/bivex/DPX-Elixir)** | **Elixir** (OTP 25 - 27+) | **GenServer, DynamicSupervisor, Actor Fault Tolerance** |
| **[`DPX-Erlang`](https://github.com/bivex/DPX-Erlang)** | **Erlang/OTP** (24 - 27+) | **OTP Behaviors, Supervision Trees, Message Passing** |
| **[`DPX-C`](https://github.com/bivex/DPX-C)** | **C** (C99 - C23) | **Opaque Structs, VTables, MISRA/CERT Safety, Arena Allocators** |
| **[`DPX-Cpp`](https://github.com/bivex/DPX-Cpp)** | **C++** (C++14 - C++20) | **CRTP, Policy-Based Design, RAII Memory Safety, ANTLR4 AST** |
| **[`DPX-Java`](https://github.com/bivex/DPX-Java)** | **Java** (17 - 23+) | **Virtual Threads, Spring Boot / Jakarta EE, GoF Patterns** |
| **[`DPX`](https://github.com/bivex/DPX)** | **Clojure** / Meta Engine | **Pure Functional, Multimethods, Homoiconic Macro Architecture** |
---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.


## 🌐 The DPX Multi-Language Static Analysis Family (31 Languages)

| # | Language | Repository | Ecosystem & Focus |
|:---:|---|---|---|
| 1 | **Clojure** | [`bivex/DPX`](https://github.com/bivex/DPX) | Lisp S-Expressions, Protocols, Multimethods |
| 2 | **C** | [`bivex/DPX-C`](https://github.com/bivex/DPX-C) | Memory Safety, Struct VTables, Idiomatic C11/C23 |
| 3 | **Cairo** | [`bivex/DPX-Cairo`](https://github.com/bivex/DPX-Cairo) | Starknet Smart Contracts, ZK-Rollup Invariants |
| 4 | **C++** | [`bivex/DPX-Cpp`](https://github.com/bivex/DPX-Cpp) | RAII, CRTP, Concepts, Modern C++20/23 |
| 5 | **C#** | [`bivex/DPX-CSharp`](https://github.com/bivex/DPX-CSharp) | .NET 9, Roslyn AST, Linq, Records |
| 6 | **Dart** | [`bivex/DPX-Dart`](https://github.com/bivex/DPX-Dart) | Dart 3.x, Flutter, BLoC, Riverpod, Isolates |
| 7 | **Elixir** | [`bivex/DPX-Elixir`](https://github.com/bivex/DPX-Elixir) | BEAM OTP, GenServer, Supervisors |
| 8 | **Erlang** | [`bivex/DPX-Erlang`](https://github.com/bivex/DPX-Erlang) | Fault Tolerance, Actor Model, OTP Behaviors |
| 9 | **Gleam** | [`bivex/DPX-Gleam`](https://github.com/bivex/DPX-Gleam) | Type-Safe BEAM, Actor Concurrency |
| 10 | **Go** | [`bivex/DPX-Go`](https://github.com/bivex/DPX-Go) | Goroutines, Channels, Composition, Interfaces |
| 11 | **Haskell** | [`bivex/DPX-Haskell`](https://github.com/bivex/DPX-Haskell) | Pure Functional, Monads, Typeclasses, Arrows |
| 12 | **Huff** | [`bivex/DPX-Huff`](https://github.com/bivex/DPX-Huff) | Low-Level EVM Bytecode & Opcodes |
| 13 | **Idris 2** | [`bivex/DPX-Idris2`](https://github.com/bivex/DPX-Idris2) | Dependent Types, QTT Linear Protocols, Totality, Proofs |
| 14 | **Java** | [`bivex/DPX-Java`](https://github.com/bivex/DPX-Java) | Spring Boot, Enterprise Java, JVM Invariants |
| 15 | **Julia** | [`bivex/DPX-Julia`](https://github.com/bivex/DPX-Julia) | Multiple Dispatch, Scientific Computing |
| 16 | **Kotlin** | [`bivex/DPX-Kotlin`](https://github.com/bivex/DPX-Kotlin) | Coroutines, Multiplatform, Functional DSLs |
| 17 | **Lua** | [`bivex/DPX-Lua`](https://github.com/bivex/DPX-Lua) | Metatables, Coroutines, LuaJIT, Neovim |
| 18 | **Mojo** | [`bivex/DPX-Mojo`](https://github.com/bivex/DPX-Mojo) | SIMD Hardware, Memory Lifetimes, AI Systems |
| 19 | **Move** | [`bivex/DPX-Move`](https://github.com/bivex/DPX-Move) | Aptos & Sui Resource Safety, Linear Types |
| 20 | **OCaml** | [`bivex/DPX-OCaml`](https://github.com/bivex/DPX-OCaml) | Algebraic Data Types, Functors, Polymorphism |
| 21 | **PHP** | [`bivex/DPX-Php`](https://github.com/bivex/DPX-Php) | Modern PHP 8.4, Attributes, Traits, Laravel |
| 22 | **Puppet** | [`bivex/DPX-Puppet`](https://github.com/bivex/DPX-Puppet) | Puppet DSL, Roles/Profiles, IaC Security, Hiera |
| 23 | **Python** | [`bivex/DPX-Py`](https://github.com/bivex/DPX-Py) | Metaprogramming, Protocols, Hexagonal DDD |
| 24 | **Ruby** | [`bivex/DPX-Ruby`](https://github.com/bivex/DPX-Ruby) | Ruby 3.x, Rails, Metaprogramming, Dry-RB, Security |
| 25 | **Rust** | [`bivex/DPX-Rust`](https://github.com/bivex/DPX-Rust) | Zero-Cost Abstractions, Borrow Checker, Traits |
| 26 | **Solidity** | [`bivex/DPX-Solidity`](https://github.com/bivex/DPX-Solidity) | DeFi Security, Reentrancy, EVM Yul/Assembly |
| 27 | **SQL** | [`bivex/DPX-SQL`](https://github.com/bivex/DPX-SQL) | PostgreSQL, MySQL, SQLite, T-SQL, PL/SQL |
| 28 | **Swift** | [`bivex/DPX-Swift`](https://github.com/bivex/DPX-Swift) | Protocol-Oriented Programming, Actors |
| 29 | **TypeScript** | [`bivex/DPX-TypeScript`](https://github.com/bivex/DPX-TypeScript) | Generics, Conditional Types, Clean Architecture |
| 30 | **Yul** | [`bivex/DPX-Yul`](https://github.com/bivex/DPX-Yul) | **EVM Intermediate Representation Optimization** |
| 31 | **Zig** | [`bivex/DPX-Zig`](https://github.com/bivex/DPX-Zig) | Comptime, Manual Memory Allocators, C ABI |
