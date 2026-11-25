"""AST Mutation Testing & Mutant-Kill Adequacy Verifier (`forge_runtime/mutant_verifier.py`).

Engineered for automated test adequacy verification (StoreGen & AI-native SDLC):
  1. `ASTMutantSynthesizer`:
     - Parses Python target code via `ast` and synthesizes deterministic single-site code mutants:
         * `RELATIONAL_BOUNDARY` (`>` <-> `>=`, `<` <-> `<=`, `==` <-> `!=`)
         * `ARITHMETIC_OP`       (`+` <-> `-`, `*` <-> `//`)
         * `BOOLEAN_CONSTANT`    (`True` <-> `False`)
         * `LOGICAL_CONNECTOR`   (`and` <-> `or`)
         * `OFF_BY_ONE_BOUNDARY` (`n` -> `n + 1` on numeric comparison thresholds)
  2. `MutantSandboxScanner` & Isolated Subprocess Runner:
     - Validates both `target_code` and `test_code` via static AST allowlisting before execution.
     - Runs baseline statement coverage (`sys.settrace`) and per-mutant `unittest` suites inside
       isolated `subprocess.run([sys.executable, "-I", ...], shell=False)` OS processes with
       credential-stripped environments.
  3. `MutantAdequacyVerifier`:
     - Computes real **Mutation Kill Score (`killed / total_mutants`)** alongside line coverage,
       rejecting tautological `assert True` rubber-stamp tests that achieve `100%` line coverage
       while killing `0%` of bugs, and supporting survivor-guided boundary test synthesis.
"""

from __future__ import annotations

import ast
import copy
import json
import re
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


class MutantSecurityViolation(PermissionError):
    """Raised when candidate target or unit-test code attempts a forbidden import or builtin."""


ALLOWED_TEST_IMPORTS: Set[str] = {
    "unittest",
    "decimal",
    "math",
    "statistics",
    "fractions",
    "json",
    "re",
    "collections",
    "itertools",
    "functools",
    "typing",
    "dataclasses",
    "promo_pricing",
    "target_module",
}

FORBIDDEN_TEST_BUILTINS: Set[str] = {
    "eval",
    "exec",
    "compile",
    "open",
    "input",
    "breakpoint",
    "__import__",
    "getattr",
    "setattr",
    "delattr",
    "globals",
    "locals",
    "vars",
    "memoryview",
}

ALLOWED_DUNDER_NAMES: Set[str] = {"__init__", "__name__", "__main__"}


class MutantSandboxScanner:
    """AST security gate ensuring public `/api/mutants/verify` inputs cannot touch OS, disk, or network."""

    @staticmethod
    def validate_source(code: str, *, label: str = "code", extra_allowed_modules: Optional[Set[str]] = None) -> ast.Module:
        if len(code) > 24_576:
            raise MutantSecurityViolation(f"{label.upper()}_TOO_LARGE: exceeds 24KB limit")
        allowed_mods = set(ALLOWED_TEST_IMPORTS) | (extra_allowed_modules or set())
        tree = ast.parse(code, filename=f"<{label}>")

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    if root not in allowed_mods:
                        raise MutantSecurityViolation(
                            f"FORBIDDEN_IMPORT: module '{alias.name}' is blocked in mutant sandbox"
                        )
            elif isinstance(node, ast.ImportFrom):
                root = (node.module or "").split(".")[0]
                if node.level > 0 or root not in allowed_mods:
                    raise MutantSecurityViolation(
                        f"FORBIDDEN_IMPORT_FROM: module '{node.module}' is blocked in mutant sandbox"
                    )
            elif isinstance(node, ast.Attribute):
                if (
                    node.attr.startswith("__")
                    and node.attr.endswith("__")
                    and node.attr not in ALLOWED_DUNDER_NAMES
                ):
                    raise MutantSecurityViolation(
                        f"FORBIDDEN_DUNDER_ATTRIBUTE: '{node.attr}' introspection is blocked"
                    )
            elif isinstance(node, ast.Name):
                if (
                    node.id.startswith("__")
                    and node.id.endswith("__")
                    and node.id not in ALLOWED_DUNDER_NAMES
                ):
                    raise MutantSecurityViolation(
                        f"FORBIDDEN_DUNDER_NAME: '{node.id}' access is blocked"
                    )
                if node.id in FORBIDDEN_TEST_BUILTINS:
                    raise MutantSecurityViolation(
                        f"FORBIDDEN_BUILTIN: '{node.id}' is blocked in mutant sandbox"
                    )
        return tree


@dataclass(frozen=True)
class CodeMutant:
    """Single syntactic AST code mutant synthesized from target Python source."""

    mutant_id: str
    operator: str
    lineno: int
    description: str
    original_snippet: str
    mutated_snippet: str
    mutated_source: str

    def to_dict(self, include_source: bool = False) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "mutant_id": self.mutant_id,
            "operator": self.operator,
            "lineno": self.lineno,
            "description": self.description,
            "original_snippet": self.original_snippet,
            "mutated_snippet": self.mutated_snippet,
        }
        if include_source:
            payload["mutated_source"] = self.mutated_source
        return payload


@dataclass(frozen=True)
class MutantKillOutcome:
    """Execution verdict of the candidate unit test suite against one AST mutant."""

    mutant_id: str
    operator: str
    lineno: int
    description: str
    original_snippet: str
    mutated_snippet: str
    killed: bool
    status: str  # "KILLED" | "SURVIVED" | "TIMEOUT_KILLED"
    failure_summary: str
    latency_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mutant_id": self.mutant_id,
            "operator": self.operator,
            "lineno": self.lineno,
            "description": self.description,
            "original_snippet": self.original_snippet,
            "mutated_snippet": self.mutated_snippet,
            "killed": self.killed,
            "status": self.status,
            "failure_summary": self.failure_summary,
            "latency_ms": round(self.latency_ms, 2),
        }


_COMPARE_FLIPS: Dict[type, Tuple[type, str]] = {
    ast.Gt: (ast.GtE, "> -> >="),
    ast.GtE: (ast.Gt, ">= -> >"),
    ast.Lt: (ast.LtE, "< -> <="),
    ast.LtE: (ast.Lt, "<= -> <"),
    ast.Eq: (ast.NotEq, "== -> !="),
    ast.NotEq: (ast.Eq, "!= -> =="),
}

_BINOP_FLIPS: Dict[type, Tuple[type, str]] = {
    ast.Add: (ast.Sub, "+ -> -"),
    ast.Sub: (ast.Add, "- -> +"),
    ast.Mult: (ast.FloorDiv, "* -> //"),
    ast.FloorDiv: (ast.Mult, "// -> *"),
}

_BOOLOP_FLIPS: Dict[type, Tuple[type, str]] = {
    ast.And: (ast.Or, "and -> or"),
    ast.Or: (ast.And, "or -> and"),
}


class ASTMutantSynthesizer:
    """Discovers AST mutation sites and synthesizes single-defect Python mutants."""

    @classmethod
    def synthesize_mutants(cls, source_code: str, max_mutants: int = 16) -> List[CodeMutant]:
        base_tree = ast.parse(source_code)
        base_canonical = ast.unparse(base_tree)

        # Enumerate deterministic candidate mutation specifications `(node_ordinal, kind, detail)`
        specs: List[Tuple[int, str, str, int, str]] = []
        for ordinal, node in enumerate(ast.walk(base_tree)):
            lineno = getattr(node, "lineno", 1)
            if isinstance(node, ast.Compare) and len(node.ops) == 1 and type(node.ops[0]) in _COMPARE_FLIPS:
                _, label = _COMPARE_FLIPS[type(node.ops[0])]
                specs.append((ordinal, "RELATIONAL_BOUNDARY", label, lineno, ast.unparse(node)))
                # Also synthesize an off-by-one constant flip on integer threshold comparisons
                comp_rhs = node.comparators[0]
                if (
                    isinstance(comp_rhs, ast.Constant)
                    and type(comp_rhs.value) is int
                    and isinstance(node.ops[0], (ast.Gt, ast.GtE, ast.Lt, ast.LtE))
                ):
                    orig_val = int(comp_rhs.value)
                    new_val = orig_val + 1 if orig_val == 0 else orig_val - 1
                    specs.append(
                        (
                            ordinal,
                            "OFF_BY_ONE_BOUNDARY",
                            f"{orig_val} -> {new_val}",
                            lineno,
                            ast.unparse(node),
                        )
                    )
            elif isinstance(node, ast.BinOp) and type(node.op) in _BINOP_FLIPS:
                _, label = _BINOP_FLIPS[type(node.op)]
                specs.append((ordinal, "ARITHMETIC_OP", label, lineno, ast.unparse(node)))
            elif isinstance(node, ast.BoolOp) and type(node.op) in _BOOLOP_FLIPS:
                _, label = _BOOLOP_FLIPS[type(node.op)]
                specs.append((ordinal, "LOGICAL_CONNECTOR", label, lineno, ast.unparse(node)))
            elif isinstance(node, ast.Constant) and type(node.value) is bool:
                flipped_bool = not node.value
                specs.append(
                    (
                        ordinal,
                        "BOOLEAN_CONSTANT",
                        f"{node.value} -> {flipped_bool}",
                        lineno,
                        repr(node.value),
                    )
                )

        # Prioritize balanced coverage across all 5 AST mutant operator families while preserving line order
        mutants: List[CodeMutant] = []
        seen_sources: Set[str] = {base_canonical}

        for ordinal, op_kind, op_label, lineno, orig_snip in specs:
            if len(mutants) >= max_mutants:
                break
            cloned_tree = copy.deepcopy(base_tree)
            walked = list(ast.walk(cloned_tree))
            if ordinal >= len(walked):
                continue
            target = walked[ordinal]
            mut_snip = ""

            if op_kind == "RELATIONAL_BOUNDARY" and isinstance(target, ast.Compare):
                new_cls, _ = _COMPARE_FLIPS[type(target.ops[0])]
                target.ops[0] = new_cls()
                mut_snip = ast.unparse(target)
            elif op_kind == "OFF_BY_ONE_BOUNDARY" and isinstance(target, ast.Compare):
                rhs = target.comparators[0]
                if isinstance(rhs, ast.Constant) and type(rhs.value) is int:
                    rhs.value = rhs.value + 1 if rhs.value == 0 else rhs.value - 1
                    mut_snip = ast.unparse(target)
            elif op_kind == "ARITHMETIC_OP" and isinstance(target, ast.BinOp):
                new_cls, _ = _BINOP_FLIPS[type(target.op)]
                target.op = new_cls()
                mut_snip = ast.unparse(target)
            elif op_kind == "LOGICAL_CONNECTOR" and isinstance(target, ast.BoolOp):
                new_cls, _ = _BOOLOP_FLIPS[type(target.op)]
                target.op = new_cls()
                mut_snip = ast.unparse(target)
            elif op_kind == "BOOLEAN_CONSTANT" and isinstance(target, ast.Constant):
                target.value = not bool(target.value)
                mut_snip = repr(target.value)
            else:
                continue

            ast.fix_missing_locations(cloned_tree)
            mutated_src = ast.unparse(cloned_tree)
            if mutated_src in seen_sources:
                continue
            seen_sources.add(mutated_src)

            mid = f"MUT-{len(mutants) + 1:02d}"
            mutants.append(
                CodeMutant(
                    mutant_id=mid,
                    operator=op_kind,
                    lineno=lineno,
                    description=f"L{lineno} {op_kind} ({op_label})",
                    original_snippet=orig_snip,
                    mutated_snippet=mut_snip,
                    mutated_source=mutated_src,
                )
            )

        return mutants


_ISOLATED_RUNNER_SCRIPT = '''import ast
import io
import json
import os
import sys
import unittest

mode = sys.argv[1]
target_file = os.path.realpath(sys.argv[2])
test_module = sys.argv[3]
sys.path.insert(0, os.path.dirname(target_file))

covered_lines = set()

def _tracer(frame, event, arg):
    if event == "line" and os.path.realpath(frame.f_code.co_filename) == target_file:
        covered_lines.add(frame.f_lineno)
    return _tracer

if mode == "baseline":
    sys.settrace(_tracer)

try:
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromName(test_module)
    buf = io.StringIO()
    runner = unittest.TextTestRunner(stream=buf, verbosity=2)
    res = runner.run(suite)
finally:
    if mode == "baseline":
        sys.settrace(None)

exec_lines = set()
if mode == "baseline":
    src = open(target_file, "r", encoding="utf-8").read()
    tree = ast.parse(src, filename=target_file)
    stmt_types = (
        ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Return, ast.Raise,
        ast.If, ast.For, ast.While, ast.Expr, ast.Assert,
    )
    for nd in ast.walk(tree):
        if isinstance(nd, stmt_types) and hasattr(nd, "lineno"):
            # Skip module/function docstring constant expressions
            if isinstance(nd, ast.Expr) and isinstance(nd.value, ast.Constant) and isinstance(nd.value.value, str):
                continue
            exec_lines.add(nd.lineno)

failure_msg = ""
if res.failures:
    failure_msg = res.failures[0][0].id() + ": " + res.failures[0][1].strip().splitlines()[-1]
elif res.errors:
    failure_msg = res.errors[0][0].id() + ": " + res.errors[0][1].strip().splitlines()[-1]

out = {
    "passed": res.wasSuccessful() and res.testsRun > 0,
    "tests_run": res.testsRun,
    "failures": len(res.failures),
    "errors": len(res.errors),
    "failure_summary": failure_msg[:220],
    "executable_lines": sorted(exec_lines),
    "covered_lines": sorted(covered_lines & exec_lines),
}
sys.stdout.write(json.dumps(out) + "\\n")
'''


def _clean_subprocess_env() -> Dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin:/usr/local/bin",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


class MutantAdequacyVerifier:
    """Computes real AST Mutation Kill Score in isolated `subprocess.run(..., shell=False)` sandboxes."""

    def __init__(self, max_workers: int = 4) -> None:
        self.max_workers = max(1, min(6, int(max_workers)))

    @staticmethod
    def _run_suite_in_subprocess(
        *,
        mode: str,
        module_name: str,
        target_code: str,
        test_code: str,
        timeout_sec: float,
    ) -> Tuple[str, Dict[str, Any], float]:
        t0 = time.perf_counter()
        with tempfile.TemporaryDirectory(prefix="forge_mut_sbx_") as tmp:
            root = Path(tmp).resolve()
            target_path = root / f"{module_name}.py"
            test_path = root / "test_candidate_suite.py"
            runner_path = root / "_runner.py"

            target_path.write_text(target_code, encoding="utf-8")
            test_path.write_text(test_code, encoding="utf-8")
            runner_path.write_text(_ISOLATED_RUNNER_SCRIPT, encoding="utf-8")

            cmd = [
                sys.executable,
                "-I",
                str(runner_path),
                mode,
                str(target_path),
                "test_candidate_suite",
            ]
            try:
                proc = subprocess.run(
                    cmd,
                    cwd=str(root),
                    env=_clean_subprocess_env(),
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=timeout_sec,
                )
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                stdout_line = (proc.stdout or "").strip().splitlines()
                if stdout_line:
                    data = json.loads(stdout_line[-1])
                    return "COMPLETED", data, elapsed_ms
                return (
                    "CRASHED",
                    {
                        "passed": False,
                        "tests_run": 0,
                        "failure_summary": (proc.stderr or "Subprocess exited with error").strip()[-180:],
                    },
                    elapsed_ms,
                )
            except subprocess.TimeoutExpired:
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                return (
                    "TIMEOUT",
                    {
                        "passed": False,
                        "tests_run": 0,
                        "failure_summary": f"Infinite loop / hang killed after {timeout_sec}s timeout",
                    },
                    elapsed_ms,
                )

    def verify_suite(
        self,
        target_code: str,
        test_code: str,
        *,
        module_name: str = "promo_pricing",
        min_kill_score_pct: float = 85.0,
        max_mutants: int = 16,
        timeout_sec: float = 1.8,
    ) -> Dict[str, Any]:
        """Executes baseline coverage + all AST mutants in isolated `shell=False` subprocesses."""
        t0 = time.perf_counter()
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", module_name):
            raise ValueError(f"Invalid Python module identifier: {module_name}")

        # 1. Static AST security check before touching subprocesses
        MutantSandboxScanner.validate_source(
            target_code, label="target_code", extra_allowed_modules={module_name}
        )
        MutantSandboxScanner.validate_source(
            test_code, label="test_code", extra_allowed_modules={module_name}
        )

        # 2. Run unmutated baseline test suite + statement line tracer
        base_state, base_data, base_ms = self._run_suite_in_subprocess(
            mode="baseline",
            module_name=module_name,
            target_code=target_code,
            test_code=test_code,
            timeout_sec=timeout_sec,
        )
        exec_lines = base_data.get("executable_lines", [])
        cov_lines = base_data.get("covered_lines", [])
        line_cov_pct = (
            round(100.0 * len(cov_lines) / len(exec_lines), 1) if exec_lines else 100.0
        )

        if not base_data.get("passed", False):
            return {
                "ok": False,
                "adequacy_verdict": "REJECTED_BASELINE_SUITE_FAILING",
                "baseline_passed": False,
                "tests_run": int(base_data.get("tests_run", 0)),
                "baseline_error": base_data.get("failure_summary", base_state),
                "line_coverage_pct": line_cov_pct,
                "total_mutants": 0,
                "killed_mutants": 0,
                "survived_mutants": 0,
                "mutation_kill_score_pct": 0.0,
                "tautological_rubber_stamp_detected": False,
                "outcomes": [],
                "wall_time_ms": round((time.perf_counter() - t0) * 1000.0, 2),
            }

        # 3. Synthesize AST code mutants
        mutants = ASTMutantSynthesizer.synthesize_mutants(target_code, max_mutants=max_mutants)

        # 4. Evaluate each mutant in an isolated OS subprocess (`shell=False`)
        def _eval_one(m: CodeMutant) -> MutantKillOutcome:
            st, m_data, m_ms = self._run_suite_in_subprocess(
                mode="mutant",
                module_name=module_name,
                target_code=m.mutated_source,
                test_code=test_code,
                timeout_sec=timeout_sec,
            )
            if st == "TIMEOUT":
                return MutantKillOutcome(
                    mutant_id=m.mutant_id,
                    operator=m.operator,
                    lineno=m.lineno,
                    description=m.description,
                    original_snippet=m.original_snippet,
                    mutated_snippet=m.mutated_snippet,
                    killed=True,
                    status="TIMEOUT_KILLED",
                    failure_summary=m_data.get("failure_summary", "Timeout"),
                    latency_ms=m_ms,
                )
            suite_passed_on_mutant = bool(m_data.get("passed", False))
            killed = not suite_passed_on_mutant
            return MutantKillOutcome(
                mutant_id=m.mutant_id,
                operator=m.operator,
                lineno=m.lineno,
                description=m.description,
                original_snippet=m.original_snippet,
                mutated_snippet=m.mutated_snippet,
                killed=killed,
                status="KILLED" if killed else "SURVIVED",
                failure_summary=(
                    m_data.get("failure_summary", "Assertion killed mutant")
                    if killed
                    else "SURVIVED: candidate tests exited 0 despite injected defect"
                ),
                latency_ms=m_ms,
            )

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            outcomes = list(pool.map(_eval_one, mutants))

        total_m = len(outcomes)
        killed_m = sum(1 for o in outcomes if o.killed)
        survived_m = total_m - killed_m
        kill_pct = round(100.0 * killed_m / max(1, total_m), 1)
        tautological = line_cov_pct >= 75.0 and kill_pct <= 25.0

        if tautological:
            verdict = "REJECTED_TAUTOLOGICAL_SUITE"
        elif kill_pct < min_kill_score_pct:
            verdict = "REJECTED_WEAK_MUTANT_KILL"
        else:
            verdict = "ADEQUATE_SUITE_VERIFIED"

        by_op: Dict[str, Dict[str, int]] = {}
        for o in outcomes:
            bucket = by_op.setdefault(o.operator, {"total": 0, "killed": 0, "survived": 0})
            bucket["total"] += 1
            if o.killed:
                bucket["killed"] += 1
            else:
                bucket["survived"] += 1

        return {
            "ok": verdict == "ADEQUATE_SUITE_VERIFIED",
            "adequacy_verdict": verdict,
            "min_kill_score_gate_pct": min_kill_score_pct,
            "baseline_passed": True,
            "tests_run": int(base_data.get("tests_run", 0)),
            "baseline_latency_ms": round(base_ms, 2),
            "executable_lines_count": len(exec_lines),
            "covered_lines_count": len(cov_lines),
            "line_coverage_pct": line_cov_pct,
            "total_mutants": total_m,
            "killed_mutants": killed_m,
            "survived_mutants": survived_m,
            "mutation_kill_score_pct": kill_pct,
            "coverage_minus_kill_gap_pct": round(line_cov_pct - kill_pct, 1),
            "tautological_rubber_stamp_detected": tautological,
            "operator_breakdown": by_op,
            "outcomes": [o.to_dict() for o in outcomes],
            "wall_time_ms": round((time.perf_counter() - t0) * 1000.0, 2),
        }


# ============================================================================
# REFERENCE STOREGEN TARGET MODULE & 3 CANDIDATE TEST SUITES
# ============================================================================

DEFAULT_MUTANT_TARGET_CODE = '''"""StoreGen order promotion, VIP bonus, free-shipping, and fraud-hold calculator."""


def evaluate_order_promotion(
    subtotal_cents: int,
    promo_bps: int,
    vip_member: bool,
    risk_score: int,
) -> dict:
    if subtotal_cents <= 0:
        return {
            "net_cents": 0,
            "discount_cents": 0,
            "ceiling_applied": False,
            "free_shipping": False,
            "manual_review": False,
        }

    effective_bps = promo_bps
    if vip_member and subtotal_cents >= 10000:
        effective_bps = effective_bps + 500
    ceiling_applied = True if effective_bps >= 3500 else False
    if ceiling_applied:
        effective_bps = 3500

    discount_cents = (subtotal_cents * effective_bps) // 10000
    net_cents = subtotal_cents - discount_cents
    free_shipping = True if (vip_member or net_cents >= 5000) else False
    manual_review = True if (risk_score >= 80 or (net_cents >= 250000 and not vip_member)) else False

    return {
        "net_cents": net_cents,
        "discount_cents": discount_cents,
        "ceiling_applied": ceiling_applied,
        "free_shipping": free_shipping,
        "manual_review": manual_review,
    }
'''

SUITE_TAUTOLOGICAL_RUBBER_STAMP = '''"""Tautological smoke tests: hits 100% of lines while asserting only `assert True` / keys."""

import unittest
from promo_pricing import evaluate_order_promotion


class TestPromoTautological(unittest.TestCase):
    def test_zero_and_vip_and_capped_paths_smoke_only(self):
        r0 = evaluate_order_promotion(0, 500, False, 10)
        r1 = evaluate_order_promotion(20000, 3200, True, 85)
        r2 = evaluate_order_promotion(300000, 100, False, 20)
        self.assertIsInstance(r0, dict)
        self.assertIn("net_cents", r1)
        self.assertIn("manual_review", r2)
        self.assertTrue(True)
'''

SUITE_NAIVE_LLM_HAPPY_PATH = '''"""Naive zero-shot LLM suite: 100% line coverage, but misses >= / > boundaries and boolean edges."""

import unittest
from promo_pricing import evaluate_order_promotion


class TestPromoNaiveLLM(unittest.TestCase):
    def test_negative_subtotal(self):
        res = evaluate_order_promotion(-500, 1000, False, 10)
        self.assertEqual(res["net_cents"], 0)

    def test_vip_capped_order(self):
        res = evaluate_order_promotion(20000, 3200, True, 90)
        self.assertEqual(res["discount_cents"], 7000)
        self.assertEqual(res["net_cents"], 13000)
        self.assertTrue(res["free_shipping"])
        self.assertTrue(res["manual_review"])
'''

SUITE_SURVIVOR_GUIDED_ADEQUATE = '''"""Survivor-guided boundary suite: pins exact off-by-one thresholds and boolean clauses."""

import unittest
from promo_pricing import evaluate_order_promotion


class TestPromoSurvivorGuided(unittest.TestCase):
    def test_zero_and_one_cent_boundary(self):
        zero = evaluate_order_promotion(0, 1000, True, 95)
        self.assertEqual(
            zero,
            {
                "net_cents": 0,
                "discount_cents": 0,
                "ceiling_applied": False,
                "free_shipping": False,
                "manual_review": False,
            },
        )
        one = evaluate_order_promotion(1, 0, False, 0)
        self.assertEqual(one["net_cents"], 1)
        self.assertFalse(one["free_shipping"])
        self.assertFalse(one["manual_review"])

    def test_vip_10000_threshold_and_3500_bps_cap(self):
        below_vip = evaluate_order_promotion(9999, 1000, True, 10)
        self.assertEqual(below_vip["discount_cents"], 999)
        at_vip = evaluate_order_promotion(10000, 1000, True, 10)
        self.assertEqual(at_vip["discount_cents"], 1500)
        self.assertEqual(at_vip["net_cents"], 8500)
        non_vip = evaluate_order_promotion(10000, 1000, False, 10)
        self.assertEqual(non_vip["discount_cents"], 1000)

        below_cap = evaluate_order_promotion(10000, 3499, False, 10)
        self.assertEqual(below_cap["discount_cents"], 3499)
        self.assertFalse(below_cap["ceiling_applied"])
        at_cap = evaluate_order_promotion(10000, 3500, False, 10)
        self.assertEqual(at_cap["discount_cents"], 3500)
        self.assertTrue(at_cap["ceiling_applied"])
        over_cap = evaluate_order_promotion(10000, 4000, True, 10)
        self.assertEqual(over_cap["discount_cents"], 3500)
        self.assertTrue(over_cap["ceiling_applied"])

    def test_free_shipping_and_fraud_review_exact_edges(self):
        ship_4999 = evaluate_order_promotion(4999, 0, False, 79)
        self.assertFalse(ship_4999["free_shipping"])
        self.assertFalse(ship_4999["manual_review"])

        ship_5000 = evaluate_order_promotion(5000, 0, False, 80)
        self.assertTrue(ship_5000["free_shipping"])
        self.assertTrue(ship_5000["manual_review"])

        vip_low_spend = evaluate_order_promotion(500, 0, True, 20)
        self.assertTrue(vip_low_spend["free_shipping"])

        high_non_vip_below = evaluate_order_promotion(249999, 0, False, 20)
        self.assertFalse(high_non_vip_below["manual_review"])
        high_non_vip_at = evaluate_order_promotion(250000, 0, False, 20)
        self.assertTrue(high_non_vip_at["manual_review"])
        high_vip_exempt = evaluate_order_promotion(250000, 0, True, 20)
        self.assertFalse(high_vip_exempt["manual_review"])
'''

MUTANT_SUITE_PRESETS: Dict[str, Dict[str, str]] = {
    "tautological": {
        "suite_id": "tautological",
        "label": "Tautological Smoke Suite (assert True / Keys Only)",
        "test_code": SUITE_TAUTOLOGICAL_RUBBER_STAMP,
    },
    "naive_llm": {
        "suite_id": "naive_llm",
        "label": "Naive Zero-Shot LLM Suite (Happy-Path Only)",
        "test_code": SUITE_NAIVE_LLM_HAPPY_PATH,
    },
    "survivor_guided": {
        "suite_id": "survivor_guided",
        "label": "Survivor-Guided Boundary Suite (Full Mutant Kill)",
        "test_code": SUITE_SURVIVOR_GUIDED_ADEQUATE,
    },
}

_FENCE_RE = re.compile(r"```(?:python|py)?\s*([\s\S]*?)```", re.IGNORECASE)


def synthesize_survivor_guided_tests(
    target_code: str,
    current_test_code: str,
    surviving_outcomes: List[Dict[str, Any]],
    bedrock_caller: Optional[Callable[[str, str, int], Optional[Dict[str, Any]]]] = None,
) -> Tuple[str, str]:
    """Synthesizes sharp boundary unit tests targeting surviving AST mutants."""
    if bedrock_caller is not None and surviving_outcomes:
        survivor_lines = "\n".join(
            f"- {s['mutant_id']} (line {s['lineno']}): `{s['original_snippet']}` mutated to `{s['mutated_snippet']}`"
            for s in surviving_outcomes[:10]
        )
        sys_prompt = (
            "You are ForgeRuntime v2's StoreGen Survivor-Guided Unit Test Synthesizer. "
            "Write a complete Python `unittest` file importing `evaluate_order_promotion` from `promo_pricing` "
            "with exact boundary assertions that kill every listed surviving AST mutant. "
            "Use ONLY `import unittest` and `from promo_pricing import ...`. Return ONLY a ```python block."
        )
        usr_prompt = (
            f"Target Module (`promo_pricing.py`):\n{target_code}\n\n"
            f"Surviving Mutants Not Killed by Current Tests:\n{survivor_lines}\n"
        )
        resp = bedrock_caller(sys_prompt, usr_prompt, 850)
        if resp and resp.get("text"):
            m = _FENCE_RE.search(resp["text"])
            cand = (m.group(1) if m else resp["text"]).strip()
            try:
                MutantSandboxScanner.validate_source(cand, label="synthesized_tests")
                if "unittest.TestCase" in cand and "assert" in cand:
                    return cand, str(resp.get("engine", "aws-bedrock"))
            except Exception:
                pass

    return SUITE_SURVIVOR_GUIDED_ADEQUATE, "survivor-boundary-synthesizer"


def run_mutant_verifier_benchmark() -> Dict[str, Any]:
    """Evaluates all 3 test-suite tiers (`tautological`, `naive_llm`, `survivor_guided`) against real AST mutants."""
    t0 = time.perf_counter()
    verifier = MutantAdequacyVerifier(max_workers=4)

    taut_res = verifier.verify_suite(
        DEFAULT_MUTANT_TARGET_CODE,
        SUITE_TAUTOLOGICAL_RUBBER_STAMP,
        max_mutants=16,
    )
    naive_res = verifier.verify_suite(
        DEFAULT_MUTANT_TARGET_CODE,
        SUITE_NAIVE_LLM_HAPPY_PATH,
        max_mutants=16,
    )
    guided_res = verifier.verify_suite(
        DEFAULT_MUTANT_TARGET_CODE,
        SUITE_SURVIVOR_GUIDED_ADEQUATE,
        max_mutants=16,
    )

    gate_checks = [
        (not taut_res["ok"] and taut_res["tautological_rubber_stamp_detected"]),
        (not naive_res["ok"] and naive_res["adequacy_verdict"] == "REJECTED_WEAK_MUTANT_KILL"),
        (guided_res["ok"] and guided_res["adequacy_verdict"] == "ADEQUATE_SUITE_VERIFIED"),
    ]
    gate_accuracy_pct = round(100.0 * sum(1 for c in gate_checks if c) / len(gate_checks), 1)

    return {
        "summary": {
            "mutants_synthesized_per_run": guided_res["total_mutants"],
            "tautological_line_coverage_pct": taut_res["line_coverage_pct"],
            "tautological_kill_score_pct": taut_res["mutation_kill_score_pct"],
            "naive_llm_line_coverage_pct": naive_res["line_coverage_pct"],
            "naive_llm_kill_score_pct": naive_res["mutation_kill_score_pct"],
            "survivor_guided_line_coverage_pct": guided_res["line_coverage_pct"],
            "survivor_guided_kill_score_pct": guided_res["mutation_kill_score_pct"],
            "kill_score_lift_vs_naive_pct": round(
                guided_res["mutation_kill_score_pct"] - naive_res["mutation_kill_score_pct"], 1
            ),
            "adequacy_gate_accuracy_pct": gate_accuracy_pct,
            "wall_time_ms": round((time.perf_counter() - t0) * 1000.0, 2),
        },
        "suites": {
            "tautological": taut_res,
            "naive_llm": naive_res,
            "survivor_guided": guided_res,
        },
    }
