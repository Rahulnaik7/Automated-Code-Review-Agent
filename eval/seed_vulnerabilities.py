"""Generates the seeded-vulnerability benchmark used by `eval/run_benchmark.py`.

Produces `data/benchmark/seeded_vulnerabilities.jsonl`: one JSON object per
line, each a synthetic single-file diff plus a ground-truth label.

The benchmark deliberately includes two classes of *negative* examples
that are easy for a naive pattern matcher to get wrong, since those are
exactly what should separate the hybrid pipeline's precision from the
zero-shot baseline's:

1. **Lookalike-but-safe code** — e.g. ``hashlib.sha256`` (not the weak
   ``md5``/``sha1``), parameterized SQL (not string-built), subprocess
   calls *without* ``shell=True``. A keyword-only matcher tends to still
   flag these.
2. **Test fixtures / placeholders** — e.g. ``test_password = "dummy"`` —
   which match the "hardcoded secret" shape but aren't a real credential.

Run directly to (re)generate the dataset:

    python -m eval.seed_vulnerabilities
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parents[1]
OUT_PATH = ROOT / "data" / "benchmark" / "seeded_vulnerabilities.jsonl"


def _diff(file_path: str, added_lines: List[str]) -> str:
    """Build a minimal valid unified diff adding `added_lines` to a new file."""
    body = "\n".join(f"+{line}" for line in added_lines)
    n = len(added_lines)
    return (
        f"diff --git a/{file_path} b/{file_path}\n"
        f"new file mode 100644\n"
        f"index 0000000..1111111\n"
        f"--- /dev/null\n"
        f"+++ b/{file_path}\n"
        f"@@ -0,0 +1,{n} @@\n"
        f"{body}\n"
    )


# -- vulnerable templates: (category, severity, lines_fn) --------------------
def _vulnerable_templates() -> List[Dict]:
    templates = []

    def add(category: str, severity: str, name: str, lines: List[str]):
        templates.append({"category": category, "severity": severity, "name": name, "lines": lines})

    # eval/exec
    for i, (fn, arg) in enumerate([
        ("eval", "user_expr"), ("eval", "request.args.get('expr')"), ("exec", "uploaded_code"),
        ("eval", "form_data['formula']"), ("exec", "request.data.decode()"),
    ]):
        add("eval_exec", "high", f"eval_exec_{i}", [
            f"def run_{i}(payload):",
            f"    {fn}({arg})",
        ])

    # shell injection
    for i, (path, cmd_expr) in enumerate([
        ("backup.py", '"tar -czf out.tar.gz " + target_dir'),
        ("convert.py", 'f"ffmpeg -i {filename} out.mp4"'),
        ("cleanup.py", '"rm -rf " + folder_name'),
        ("resize.py", 'f"convert {filename} -resize 50% {filename}_small"'),
        ("grep.py", '"grep -r " + pattern + " ."'),
    ]):
        add("shell_injection", "high", f"shell_{i}", [
            "import subprocess",
            f"def run_{i}(target_dir, filename=None, folder_name=None):",
            f"    cmd = {cmd_expr}",
            "    subprocess.run(cmd, shell=True)",
        ])

    # os.system
    for i, expr in enumerate(['"ping " + host', 'f"nslookup {domain}"', '"traceroute " + target_host']):
        add("shell_injection", "high", f"ossystem_{i}", [
            "import os",
            f"def check_{i}(host=None, domain=None, target_host=None):",
            f"    os.system({expr})",
        ])

    # insecure deserialization
    for i, line in enumerate([
        "data = pickle.loads(raw_bytes)",
        "cfg = yaml.load(stream)",
    ]):
        add("insecure_deserialization", "high", f"deser_{i}", [
            "import pickle" if "pickle" in line else "import yaml",
            f"def load_{i}(raw_bytes=None, stream=None):",
            f"    {line}",
            "    return data" if "data" in line else "    return cfg",
        ])

    # weak crypto
    for i, algo in enumerate(["md5", "sha1", "md5", "sha1"]):
        add("weak_crypto", "medium", f"weakhash_{i}", [
            "import hashlib",
            f"def hash_password_{i}(password):",
            f"    return hashlib.{algo}(password.encode()).hexdigest()",
        ])

    # Popen with shell=True — a known blind spot: our checks pattern-match
    # `subprocess.run`/`.run(...)`, not `subprocess.Popen`, so this is
    # expected to sometimes slip past both the baseline and our pipeline.
    add("shell_injection", "high", "popen_shell_0", [
        "import subprocess",
        "def launch(cmd_suffix):",
        '    proc = subprocess.Popen("ls -la " + cmd_suffix, shell=True)',
        "    return proc",
    ])

    # SQL injection
    for i, line in enumerate([
        'query = "SELECT * FROM users WHERE id = " + user_id',
        'query = f"SELECT * FROM orders WHERE user = {user_id}"',
        'query = "DELETE FROM sessions WHERE token = \'" + token + "\'"',
    ]):
        add("sql_injection", "critical", f"sqli_{i}", [
            f"def get_rows_{i}(user_id, cursor, token=None):",
            f"    {line}",
            "    cursor.execute(query)",
            "    return cursor.fetchall()",
        ])

    # hardcoded secrets
    for i, (var, val) in enumerate([
        ("api_key", "sk-live-29fA82hdKsoa0012"),
        ("password", "Summer2024!Prod"),
        ("secret_token", "ghp_9a8b7c6d5e4f3g2h1i0j"),
        ("db_password", "pr0d_db_Pa55word"),
        ("auth_key", "AKIA3F9X7Q2M1N8P0R5T"),
    ]):
        add("hardcoded_secret", "high", f"secret_{i}", [
            f"def connect_{i}():",
            f'    {var} = "{val}"',
            f"    return {var}",
        ])

    # performance: quadratic membership
    for i, coll in enumerate(["seen_ids", "processed", "blocked_users", "visited_nodes"]):
        add("perf_quadratic", "medium", f"perf_member_{i}", [
            f"def dedupe_{i}(items, {coll}):",
            "    result = []",
            "    for item in items:",
            f"        if item not in {coll}:",
            f"            {coll}.append(item)",
            "            result.append(item)",
            "    return result",
        ])

    # performance: string concat in loop
    for i, var in enumerate(["report", "html_output", "log_text"]):
        add("perf_string_concat", "low", f"perf_concat_{i}", [
            f"def build_{i}(rows):",
            f"    {var} = ''",
            "    for row in rows:",
            f"        {var} += str(row) + '\\n'",
            f"    return {var}",
        ])

    return templates


# -- clean / lookalike-but-safe templates ------------------------------------
def _clean_templates() -> List[Dict]:
    templates = []

    def add(category: str, name: str, lines: List[str]):
        templates.append({"category": category, "name": name, "lines": lines})

    # safe subprocess (no shell=True, list args)
    for i, args in enumerate(["['ls', '-la', target_dir]", "['git', 'status']", "['docker', 'ps']"]):
        add("safe_subprocess", f"safe_subproc_{i}", [
            "import subprocess",
            f"def run_{i}(target_dir=None):",
            f"    subprocess.run({args}, check=True)",
        ])

    # strong hashing
    for i in range(3):
        add("safe_crypto", f"safe_hash_{i}", [
            "import hashlib",
            f"def hash_value_{i}(data):",
            "    return hashlib.sha256(data.encode()).hexdigest()",
        ])

    # parameterized SQL
    for i in range(3):
        add("safe_sql", f"safe_sql_{i}", [
            f"def get_user_{i}(user_id, cursor):",
            '    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
            "    return cursor.fetchone()",
        ])

    # SQL keywords appear in a log message, never reach .execute() — a
    # keyword-only matcher is prone to flagging this; our AST check only
    # fires on an actual `.execute(...)` call site, so it should pass clean.
    add("safe_sql", "sql_in_log_message_0", [
        "import logging",
        "logger = logging.getLogger(__name__)",
        "def audit_log(user_id):",
        '    logger.info(f"Would run: SELECT * FROM users WHERE id={user_id}")',
    ])

    # md5 used for a non-security checksum/ETag, not a credential or
    # signature. A known, documented limitation: our weak-crypto rule
    # (like Bandit's B303) flags any hashlib.md5/sha1 call regardless of
    # purpose, since the AST can't see the *intent* behind the hash.
    add("safe_crypto", "md5_checksum_etag_0", [
        "import hashlib",
        "def etag_for(file_bytes):",
        "    return hashlib.md5(file_bytes).hexdigest()  # content checksum, not a security use",
    ])

    # secrets from environment (not hardcoded)
    for i, var in enumerate(["api_key", "db_password", "secret_token"]):
        add("safe_secret", f"env_secret_{i}", [
            "import os",
            f"def get_{var}_{i}():",
            f'    {var} = os.environ["{var.upper()}"]',
            f"    return {var}",
        ])

    # test fixtures that LOOK like hardcoded secrets but aren't real creds
    for i, (var, val) in enumerate([
        ("test_password", "dummy_password_for_tests"),
        ("mock_api_key", "placeholder_key_xxx"),
        ("example_token", "your_token_here"),
        ("fake_secret", "replace_me_with_real_secret"),
    ]):
        add("test_fixture", f"fixture_{i}", [
            f"def test_login_{i}():",
            f'    {var} = "{val}"',
            f"    assert authenticate(username=\"test_user\", password={var}) is not None",
        ])

    # safe deserialization
    for i in range(2):
        add("safe_deser", f"safe_deser_{i}", [
            "import json",
            f"def load_{i}(raw_text):",
            "    return json.loads(raw_text)",
        ])
    add("safe_deser", "safe_yaml_0", [
        "import yaml",
        "def load_cfg(stream):",
        "    return yaml.safe_load(stream)",
    ])

    # safe eval alternative
    add("safe_eval", "safe_literal_eval_0", [
        "import ast",
        "def parse_literal(expr):",
        "    return ast.literal_eval(expr)",
    ])

    # plain, issue-free business logic
    for i, lines in enumerate([
        [
            f"def total_price_{0}(items):",
            "    return sum(item.price * item.qty for item in items)",
        ],
        [
            f"def normalize_{1}(name):",
            "    return name.strip().lower()",
        ],
        [
            f"def is_valid_email_{2}(email):",
            "    return '@' in email and '.' in email.split('@')[-1]",
        ],
        [
            f"def unique_ids_{3}(items):",
            "    seen = set()",
            "    result = []",
            "    for item in items:",
            "        if item.id not in seen:",
            "            seen.add(item.id)",
            "            result.append(item)",
            "    return result",
        ],
        [
            "def retry_with_backoff(fn, attempts=3):",
            "    for attempt in range(attempts):",
            "        try:",
            "            return fn()",
            "        except Exception:",
            "            if attempt == attempts - 1:",
            "                raise",
        ],
        [
            "def paginate(items, page, page_size=20):",
            "    start = (page - 1) * page_size",
            "    return items[start:start + page_size]",
        ],
    ]):
        add("clean_logic", f"clean_{i}", lines)

    return templates


def build_dataset() -> List[Dict]:
    examples: List[Dict] = []

    for t in _vulnerable_templates():
        file_path = f"samples/{t['name']}.py"
        examples.append(
            {
                "id": t["name"],
                "file": file_path,
                "diff_text": _diff(file_path, t["lines"]),
                "has_issue": True,
                "category": t["category"],
                "severity": t["severity"],
            }
        )

    for t in _clean_templates():
        file_path = f"samples/{t['name']}.py"
        examples.append(
            {
                "id": t["name"],
                "file": file_path,
                "diff_text": _diff(file_path, t["lines"]),
                "has_issue": False,
                "category": t["category"],
                "severity": "none",
            }
        )

    return examples


def main() -> None:
    examples = build_dataset()
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUT_PATH.open("w", encoding="utf-8") as f:
        for ex in examples:
            f.write(json.dumps(ex) + "\n")

    n_vuln = sum(1 for e in examples if e["has_issue"])
    print(f"Wrote {len(examples)} examples ({n_vuln} with seeded issues, "
          f"{len(examples) - n_vuln} clean) to {OUT_PATH.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
