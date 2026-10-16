from src.analysis.ast_checks import analyze_source


def _rules(findings):
    return {f["rule"] for f in findings}


def test_flags_eval():
    findings = analyze_source("def f(x):\n    eval(x)\n", "f.py")
    assert "AST-EVAL001" in _rules(findings)


def test_flags_shell_true():
    src = "import subprocess\ndef f(cmd):\n    subprocess.run(cmd, shell=True)\n"
    findings = analyze_source(src, "f.py")
    assert "AST-SHELL001" in _rules(findings)


def test_does_not_flag_subprocess_without_shell_true():
    src = "import subprocess\ndef f():\n    subprocess.run(['ls', '-la'])\n"
    findings = analyze_source(src, "f.py")
    assert "AST-SHELL001" not in _rules(findings)


def test_flags_hardcoded_secret():
    src = 'def f():\n    password = "hunter2hunter2"\n    return password\n'
    findings = analyze_source(src, "f.py")
    assert "AST-SECRET001" in _rules(findings)


def test_does_not_flag_env_sourced_secret():
    src = (
        "import os\n"
        "def f():\n"
        "    password = os.environ['DB_PASSWORD']\n"
        "    return password\n"
    )
    findings = analyze_source(src, "f.py")
    assert "AST-SECRET001" not in _rules(findings)


def test_flags_weak_hash():
    src = "import hashlib\ndef f(data):\n    return hashlib.md5(data).hexdigest()\n"
    findings = analyze_source(src, "f.py")
    assert "AST-CRYPTO001" in _rules(findings)


def test_flags_sql_injection_via_direct_concat():
    src = (
        "def f(user_id, cursor):\n"
        '    cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n'
    )
    findings = analyze_source(src, "f.py")
    assert "AST-SQLI001" in _rules(findings)


def test_flags_sql_injection_via_variable_indirection():
    src = (
        "def f(user_id, cursor):\n"
        '    query = f"SELECT * FROM users WHERE id = {user_id}"\n'
        "    cursor.execute(query)\n"
    )
    findings = analyze_source(src, "f.py")
    assert "AST-SQLI001" in _rules(findings)


def test_does_not_flag_parameterized_sql():
    src = (
        "def f(user_id, cursor):\n"
        '    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n'
    )
    findings = analyze_source(src, "f.py")
    assert "AST-SQLI001" not in _rules(findings)


def test_flags_quadratic_membership_in_loop():
    src = (
        "def f(items, seen_ids):\n"
        "    for item in items:\n"
        "        if item not in seen_ids:\n"
        "            seen_ids.append(item)\n"
    )
    findings = analyze_source(src, "f.py")
    assert "AST-PERF002" in _rules(findings)


def test_does_not_flag_membership_against_a_set():
    src = (
        "def f(items):\n"
        "    seen = set()\n"
        "    for item in items:\n"
        "        if item.id not in seen:\n"
        "            seen.add(item.id)\n"
    )
    findings = analyze_source(src, "f.py")
    assert "AST-PERF002" not in _rules(findings)


def test_flags_string_concat_in_loop():
    src = (
        "def f(rows):\n"
        "    report = ''\n"
        "    for row in rows:\n"
        "        report += str(row)\n"
        "    return report\n"
    )
    findings = analyze_source(src, "f.py")
    assert "AST-PERF003" in _rules(findings)


def test_invalid_syntax_returns_empty_list_not_exception():
    findings = analyze_source("def f(:\n    pass", "f.py")
    assert findings == []
