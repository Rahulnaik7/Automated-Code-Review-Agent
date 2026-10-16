"""Custom AST-based checks.

These serve two purposes in the pipeline:

1. **Coverage Bandit doesn't have** — in particular performance patterns
   (quadratic membership checks, string concatenation in loops) that are
   runtime-cost issues rather than security issues.
2. **Cross-validation of Bandit findings** — for the overlapping security
   rules (``eval``/``exec``, ``shell=True``, hardcoded secrets, weak
   hashing, insecure deserialization) we re-derive the same signal from a
   second, independent code path (the AST) and only mark a Bandit finding
   as *verified* when both analysers agree. This is what lets the
   pipeline down-weight single-source, low-confidence Bandit hits instead
   of forwarding every raw hit to the reviewer.
"""
from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional

from src.graph.state import Finding

_SECRET_NAME_HINTS = ("password", "passwd", "secret", "api_key", "apikey", "token", "auth_key")
_WEAK_HASHES = {"md5", "sha1"}
_SQL_KEYWORD_RE = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE)\b", re.IGNORECASE)


class _Visitor(ast.NodeVisitor):
    def __init__(self, filepath: str) -> None:
        self.filepath = filepath
        self.findings: List[Finding] = []
        self._loop_depth = 0
        # name -> True once we've seen it assigned a dynamically-built
        # string that looks like a SQL statement (tracks the
        # `query = f"SELECT ... {x}"` then `cursor.execute(query)` pattern,
        # which a single-expression check on the call site alone would miss).
        self._sql_like_vars: Dict[str, bool] = {}
        # name -> True once assigned a set (set(), {..} literal, or a set
        # comprehension) — membership on these is already O(1), so we don't
        # flag `x in name` as a quadratic pattern for them.
        self._set_like_vars: Dict[str, bool] = {}

    # -- helpers -----------------------------------------------------
    def _add(
        self,
        node: ast.AST,
        rule: str,
        severity: str,
        confidence: str,
        message: str,
        suggested_fix: Optional[str] = None,
    ) -> None:
        line = getattr(node, "lineno", None)
        self.findings.append(
            Finding(
                id=f"ast:{rule}:{self.filepath}:{line}",
                source="ast",
                file=self.filepath,
                line=line,
                rule=rule,
                severity=severity,  # type: ignore[arg-type]
                confidence=confidence,  # type: ignore[arg-type]
                message=message,
                suggested_fix=suggested_fix,
                verified=False,
            )
        )

    # -- security ------------------------------------------------------
    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802 (ast API naming)
        func_name = self._callable_name(node.func)

        if func_name in ("eval", "exec"):
            self._add(
                node,
                "AST-EVAL001",
                "high",
                "high",
                f"Use of `{func_name}()` on potentially untrusted input can lead to "
                "arbitrary code execution.",
                suggested_fix="Avoid eval/exec; use ast.literal_eval for data, or an "
                "explicit dispatch table for behavior selection.",
            )

        if func_name == "subprocess.run" or func_name.endswith(".run"):
            if self._has_truthy_kwarg(node, "shell"):
                self._add(
                    node,
                    "AST-SHELL001",
                    "high",
                    "high",
                    "subprocess call with shell=True risks shell/command injection "
                    "if any argument is built from untrusted input.",
                    suggested_fix="Pass the command as a list and drop shell=True, "
                    "or use shlex.quote() to sanitize interpolated arguments.",
                )

        if func_name in ("os.system", "os.popen"):
            self._add(
                node,
                "AST-SHELL002",
                "high",
                "medium",
                f"`{func_name}()` executes a string via the shell; unsanitized "
                "input leads to command injection.",
            )

        if func_name in ("pickle.loads", "pickle.load", "cPickle.loads"):
            self._add(
                node,
                "AST-DESER001",
                "high",
                "medium",
                "Deserializing data with pickle allows arbitrary code execution "
                "if the input is attacker-controlled.",
                suggested_fix="Use a safe serialization format (json) or verify "
                "the data source is trusted.",
            )

        if func_name == "yaml.load" and not self._has_kwarg(node, "Loader"):
            self._add(
                node,
                "AST-DESER002",
                "high",
                "medium",
                "yaml.load() without an explicit safe Loader can instantiate "
                "arbitrary Python objects from the input.",
                suggested_fix="Use yaml.safe_load() instead.",
            )

        if func_name in ("hashlib.md5", "hashlib.sha1"):
            algo = func_name.split(".")[-1]
            if algo in _WEAK_HASHES:
                self._add(
                    node,
                    "AST-CRYPTO001",
                    "medium",
                    "high",
                    f"{algo.upper()} is cryptographically broken; unsuitable for "
                    "passwords, signatures, or integrity checks.",
                    suggested_fix="Use hashlib.sha256 (or better, a dedicated "
                    "password hash like bcrypt/argon2 for credentials).",
                )

        if func_name.endswith(".execute") and self._execute_arg_is_dynamic_sql(node):
            self._add(
                node,
                "AST-SQLI001",
                "critical",
                "medium",
                "SQL query is built via string formatting/concatenation instead "
                "of parameter binding — vulnerable to SQL injection.",
                suggested_fix="Use parameterized queries: cursor.execute(query, params).",
            )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        for target in node.targets:
            if isinstance(target, ast.Name) and self._builds_sql_dynamically(node.value):
                self._sql_like_vars[target.id] = True
            if isinstance(target, ast.Name) and self._is_set_literal(node.value):
                self._set_like_vars[target.id] = True

        for target in node.targets:
            if isinstance(target, ast.Name) and self._looks_like_secret(target.id):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    if node.value.value:  # non-empty literal, not a placeholder
                        self._add(
                            node,
                            "AST-SECRET001",
                            "high",
                            "medium",
                            f"`{target.id}` is assigned a hardcoded string literal; "
                            "looks like a hardcoded credential.",
                            suggested_fix="Load secrets from environment variables "
                            "or a secret manager, never commit them in source.",
                        )
        self.generic_visit(node)

    # -- performance -----------------------------------------------------
    def visit_For(self, node: ast.For) -> None:  # noqa: N802
        self._loop_depth += 1
        if self._loop_depth >= 2:
            self._add(
                node,
                "AST-PERF001",
                "low",
                "low",
                "Nested loop detected; verify this isn't an O(n^2)+ hot path "
                "over large collections.",
            )
        self._check_membership_in_list(node)
        self._check_string_concat_in_loop(node)
        self.generic_visit(node)
        self._loop_depth -= 1

    def visit_While(self, node: ast.While) -> None:  # noqa: N802
        self._loop_depth += 1
        self.generic_visit(node)
        self._loop_depth -= 1

    # -- internal utilities ----------------------------------------------
    def _check_membership_in_list(self, loop_node: ast.For) -> None:
        for n in ast.walk(loop_node):
            if isinstance(n, ast.Compare) and any(
                isinstance(op, (ast.In, ast.NotIn)) for op in n.ops
            ):
                # Heuristic: `x in some_name` where some_name isn't a set/dict
                # literal is a common accidental-O(n^2) pattern over a list.
                for comparator in n.comparators:
                    if isinstance(comparator, ast.Name) and not self._set_like_vars.get(
                        comparator.id
                    ):
                        self._add(
                            n,
                            "AST-PERF002",
                            "medium",
                            "low",
                            f"Membership check `in {comparator.id}` inside a loop is "
                            "O(n) per lookup on a list — O(n^2) overall. If "
                            f"`{comparator.id}` is a list, consider converting it "
                            "to a set for O(1) membership tests.",
                            suggested_fix=f"{comparator.id} = set({comparator.id})",
                        )

    def _check_string_concat_in_loop(self, loop_node: ast.For) -> None:
        for n in ast.walk(loop_node):
            if isinstance(n, ast.AugAssign) and isinstance(n.op, ast.Add):
                if isinstance(n.target, ast.Name):
                    self._add(
                        n,
                        "AST-PERF003",
                        "low",
                        "low",
                        f"String/list accumulation via `{n.target.id} += ...` inside "
                        "a loop reallocates on every iteration.",
                        suggested_fix="Accumulate into a list and ''.join(...) "
                        "after the loop (for strings), or use a comprehension.",
                    )

    @staticmethod
    def _is_set_literal(value: Optional[ast.AST]) -> bool:
        if value is None:
            return False
        if isinstance(value, (ast.Set, ast.SetComp)):
            return True
        if isinstance(value, ast.Call) and _Visitor._callable_name(value.func) == "set":
            return True
        return False

    @staticmethod
    def _looks_like_secret(name: str) -> bool:
        lowered = name.lower()
        return any(hint in lowered for hint in _SECRET_NAME_HINTS)

    @staticmethod
    def _callable_name(func: ast.AST) -> str:
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            parts = []
            node: Optional[ast.AST] = func
            while isinstance(node, ast.Attribute):
                parts.append(node.attr)
                node = node.value
            if isinstance(node, ast.Name):
                parts.append(node.id)
            return ".".join(reversed(parts))
        return ""

    @staticmethod
    def _has_kwarg(call: ast.Call, name: str) -> bool:
        return any(kw.arg == name for kw in call.keywords)

    @staticmethod
    def _has_truthy_kwarg(call: ast.Call, name: str) -> bool:
        for kw in call.keywords:
            if kw.arg == name and isinstance(kw.value, ast.Constant) and kw.value.value:
                return True
        return False

    def _execute_arg_is_dynamic_sql(self, call: ast.Call) -> bool:
        if not call.args:
            return False
        arg = call.args[0]
        if self._builds_sql_dynamically(arg):
            return True
        # `query = f"SELECT ..."` earlier, `cursor.execute(query)` here.
        if isinstance(arg, ast.Name) and self._sql_like_vars.get(arg.id):
            return True
        return False

    @staticmethod
    def _builds_sql_dynamically(value: Optional[ast.AST]) -> bool:
        """True if `value` is a dynamically-built string that looks like SQL."""
        if value is None:
            return False
        if isinstance(value, ast.JoinedStr):  # f-string
            return _Visitor._contains_sql_keyword(value)
        if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add):
            return _Visitor._contains_sql_keyword(value)
        if isinstance(value, ast.Call):
            callee = _Visitor._callable_name(value.func)
            if callee.endswith(".format"):
                return _Visitor._contains_sql_keyword(value)
        return False

    @staticmethod
    def _contains_sql_keyword(node: ast.AST) -> bool:
        """Best-effort: look for a SELECT/INSERT/UPDATE/DELETE token among the
        string constant pieces of a JoinedStr/BinOp expression."""
        for sub in ast.walk(node):
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                if _SQL_KEYWORD_RE.search(sub.value):
                    return True
        return False


def analyze_source(source: str, filepath: str) -> List[Finding]:
    """Run all AST checks against a source snippet. Returns [] on parse errors
    (diff-reconstructed snippets aren't always valid standalone Python)."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    visitor = _Visitor(filepath)
    visitor.visit(tree)
    return visitor.findings
