import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path


BEST_PRACTICES = [
    "Validate and sanitize all user inputs.",
    "Avoid hardcoded secrets; use environment variables or a secret manager.",
    "Use parameterized queries for database operations.",
    "Avoid unsafe functions like eval() and exec().",
    "Keep dependencies updated.",
    "Use proper authentication and authorization.",
    "Follow the principle of least privilege.",
]

LANGUAGE_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".java": "java",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".html": "html",
    ".htm": "html",
}

SEVERITY_ORDER = {"ERROR": 0, "HIGH": 1, "MEDIUM": 2, "WARNING": 2, "LOW": 3, "INFO": 4, "N/A": 5}
DEFAULT_IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    "node_modules",
    "venv",
    ".venv",
    "env",
}


def read_code_from_prompt():
    print(
        "Paste your code (any language). "
        "Press Ctrl+D then Enter (Linux/Mac) or Ctrl+Z then Enter (Windows) to finish:\n"
    )

    lines = []
    try:
        while True:
            lines.append(input())
    except EOFError:
        pass

    return "\n".join(lines).strip() + ("\n" if lines else "")


def read_code_from_stdin():
    return sys.stdin.read()


def prompt_for_choice():
    print("Choose an input mode:")
    print("1. Paste code")
    print("2. Scan a file")
    print("3. Scan a folder")
    print("4. Exit")

    while True:
        choice = input("\nEnter choice (1-4): ").strip()
        if choice in {"1", "2", "3", "4"}:
            return choice
        print("[!] Please enter 1, 2, 3, or 4.")


def prompt_for_path(prompt_text):
    while True:
        raw_value = input(prompt_text).strip()
        if raw_value:
            return Path(raw_value)
        print("[!] Please enter a path.")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Review source code with Semgrep and Bandit."
    )
    parser.add_argument("--file", type=Path, help="Path to a source file to review.")
    parser.add_argument(
        "--path",
        type=Path,
        help="Path to a file or folder to review recursively.",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Read code directly from standard input.",
    )
    parser.add_argument(
        "--language",
        choices=sorted(set(LANGUAGE_EXTENSIONS.values()) | {"unknown"}),
        help="Override automatic language detection.",
    )
    parser.add_argument(
        "--output",
        choices=("text", "json"),
        default="text",
        help="Choose report output format.",
    )
    parser.add_argument(
        "--no-bandit",
        action="store_true",
        help="Skip Bandit even for Python input.",
    )
    parser.add_argument(
        "--no-semgrep",
        action="store_true",
        help="Skip Semgrep.",
    )

    args = parser.parse_args()
    selected_sources = [bool(args.file), bool(args.path), bool(args.stdin)]
    if sum(selected_sources) > 1:
        parser.error("Use only one of --file, --path, or --stdin.")

    return args


def choose_interactive_args(args):
    if args.file or args.path or args.stdin:
        return args

    choice = prompt_for_choice()
    if choice == "1":
        return args
    if choice == "2":
        args.file = prompt_for_path("Enter file path: ")
        return args
    if choice == "3":
        args.path = prompt_for_path("Enter folder path: ")
        return args

    raise ValueError("Exited by user.")


def detect_language(code, source_path=None):
    lowered = code.lower()
    suffix = source_path.suffix.lower() if source_path else ""

    if suffix in LANGUAGE_EXTENSIONS:
        return LANGUAGE_EXTENSIONS[suffix], suffix
    if "import " in code and "def " in code:
        return "python", ".py"
    if "console.log" in code or "function " in code or "=>" in code:
        return "javascript", ".js"
    if "public class" in code:
        return "java", ".java"
    if "#include" in code and "<iostream>" not in code:
        return "c", ".c"
    if "using namespace std" in code or "#include <iostream>" in code:
        return "cpp", ".cpp"
    if "<html" in lowered:
        return "html", ".html"

    return "unknown", ".txt"


def language_to_extension(language):
    for extension, mapped_language in LANGUAGE_EXTENSIONS.items():
        if mapped_language == language:
            return extension
    return ".txt"


def get_recommendation(issue_text):
    issue_text = issue_text.lower()

    if "eval" in issue_text:
        return "Avoid eval(). Use safer parsing or predefined logic."
    if "exec" in issue_text:
        return "Avoid exec(). It allows arbitrary code execution."
    if "subprocess" in issue_text or "shell=true" in issue_text:
        return "Avoid shell=True. Prefer subprocess calls with explicit argument lists."
    if "sql" in issue_text:
        return "Use parameterized queries to reduce SQL injection risk."
    if "pickle" in issue_text:
        return "Avoid loading untrusted pickle data. Prefer safer formats like JSON."
    if "hardcoded" in issue_text or "password" in issue_text or "secret" in issue_text:
        return "Do not store secrets in code. Use environment variables or a secret manager."

    return "Review the finding, validate inputs, and apply the safest available pattern."


def tool_exists(command):
    return resolve_tool(command) is not None


def candidate_tool_paths(command):
    candidates = []
    executable_name = f"{command}.exe" if os.name == "nt" else command

    cwd = Path.cwd()
    candidates.append(cwd / "env" / "Scripts" / executable_name)
    candidates.append(cwd / ".venv" / "Scripts" / executable_name)
    candidates.append(cwd / "venv" / "Scripts" / executable_name)

    python_executable = Path(sys.executable)
    candidates.append(python_executable.parent / executable_name)
    candidates.append(python_executable.parent / "Scripts" / executable_name)

    return candidates


def resolve_tool(command):
    on_path = shutil.which(command)
    if on_path:
        return on_path

    for candidate in candidate_tool_paths(command):
        if candidate.exists():
            return str(candidate)

    return None


def resolve_python_executable():
    candidates = [
        Path.cwd() / "env" / "Scripts" / "python.exe",
        Path.cwd() / ".venv" / "Scripts" / "python.exe",
        Path.cwd() / "venv" / "Scripts" / "python.exe",
        Path(sys.executable),
    ]

    for candidate in candidates:
        if candidate.exists():
            return str(candidate)

    return sys.executable


def run_command(command):
    try:
        return subprocess.run(command, capture_output=True, text=True, check=False)
    except OSError as exc:
        return {"failed": True, "error": str(exc), "command": command}


def make_finding(source, tool_name, issue, line, severity, recommendation, rule_id="N/A"):
    normalized_severity = str(severity or "N/A").upper()
    return {
        "source": str(source) if source else "<stdin>",
        "tool": tool_name,
        "issue": issue,
        "line": line,
        "severity": normalized_severity,
        "rule_id": rule_id,
        "recommendation": recommendation,
    }


def severity_rank(severity):
    return SEVERITY_ORDER.get(str(severity).upper(), 99)


def dedupe_findings(findings):
    seen = set()
    unique_findings = []
    for finding in findings:
        key = (
            finding["source"],
            finding["line"],
            finding["issue"].strip().lower(),
            finding["tool"],
        )
        if key in seen:
            continue
        seen.add(key)
        unique_findings.append(finding)

    unique_findings.sort(
        key=lambda item: (
            severity_rank(item["severity"]),
            item["source"],
            item["line"] if isinstance(item["line"], int) else 0,
            item["tool"],
        )
    )
    return unique_findings


def summarize_findings(findings):
    counts = Counter(finding["severity"] for finding in findings)
    ordered_keys = sorted(counts, key=severity_rank)
    return {key: counts[key] for key in ordered_keys}


def gather_sources(args):
    if args.file:
        if not args.file.exists():
            raise FileNotFoundError(f"File not found: {args.file}")
        if not args.file.is_file():
            raise IsADirectoryError(f"Not a file: {args.file}")
        return [args.file]

    if args.path:
        if not args.path.exists():
            raise FileNotFoundError(f"Path not found: {args.path}")
        if args.path.is_file():
            return [args.path]

        files = []
        for path in args.path.rglob("*"):
            if any(part in DEFAULT_IGNORED_DIRS for part in path.parts):
                continue
            if path.is_file() and path.suffix.lower() in LANGUAGE_EXTENSIONS:
                files.append(path)
        return sorted(files)

    return []


def load_code_from_file(path):
    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return path.read_text(encoding=encoding)
        except UnicodeDecodeError:
            continue
    raise ValueError(f"Unable to decode file: {path}")


def run_semgrep_with_python(temp_path):
    python_executable = resolve_python_executable()
    semgrep_runner = (
        "import sys; "
        "sys.argv=['semgrep','scan','--config=auto','--json',"
        "'--metrics=off','--disable-version-check',sys.argv[1]]; "
        "from semgrep.main import main; "
        "main()"
    )
    return run_command([python_executable, "-c", semgrep_runner, str(temp_path)])


def run_semgrep(temp_path, display_name):
    proc = run_semgrep_with_python(temp_path)
    if isinstance(proc, dict) and proc.get("failed"):
        return [], [f"Semgrep failed to start for {display_name}: {proc['error']}"]

    if proc.returncode not in (0, 1):
        stderr = proc.stderr.strip() or "No error details returned."
        return [], [f"Semgrep failed for {display_name}: {stderr}"]

    try:
        semgrep_data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return [], [f"Could not parse Semgrep output for {display_name}."]

    findings = []
    for result in semgrep_data.get("results", []):
        message = result.get("extra", {}).get("message", "Unknown issue")
        line = result.get("start", {}).get("line", "N/A")
        severity = result.get("extra", {}).get("severity", "N/A")
        rule_id = result.get("check_id", "N/A")
        findings.append(
            make_finding(
                display_name,
                "Semgrep",
                message,
                line,
                severity,
                get_recommendation(message),
                rule_id,
            )
        )

    return findings, []


def run_bandit(temp_path, display_name):
    bandit_command = resolve_tool("bandit")
    if not bandit_command:
        return [], ["Bandit is not installed or not available on PATH."]

    proc = run_command([bandit_command, "-f", "json", str(temp_path)])
    if isinstance(proc, dict) and proc.get("failed"):
        return [], [f"Bandit failed to start for {display_name}: {proc['error']}"]

    if proc.returncode not in (0, 1):
        stderr = proc.stderr.strip() or "No error details returned."
        return [], [f"Bandit failed for {display_name}: {stderr}"]

    try:
        bandit_data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return [], [f"Could not parse Bandit output for {display_name}."]

    findings = []
    for issue in bandit_data.get("results", []):
        issue_text = issue.get("issue_text", "Unknown issue")
        line = issue.get("line_number", "N/A")
        severity = issue.get("issue_severity", "N/A")
        rule_id = issue.get("test_id", "N/A")
        findings.append(
            make_finding(
                display_name,
                "Bandit",
                issue_text,
                line,
                severity,
                get_recommendation(issue_text),
                rule_id,
            )
        )

    return findings, []


def analyze_code(code, display_name, language, extension, args):
    findings = []
    warnings = []
    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=extension, encoding="utf-8"
        ) as temp_file:
            temp_file.write(code)
            temp_path = Path(temp_file.name)

        if not args.no_semgrep:
            semgrep_findings, semgrep_warnings = run_semgrep(temp_path, display_name)
            findings.extend(semgrep_findings)
            warnings.extend(semgrep_warnings)

        if language == "python" and not args.no_bandit:
            bandit_findings, bandit_warnings = run_bandit(temp_path, display_name)
            findings.extend(bandit_findings)
            warnings.extend(bandit_warnings)
    finally:
        if temp_path and temp_path.exists():
            temp_path.unlink()

    return findings, warnings


def build_report_for_path(path, args):
    code = load_code_from_file(path)
    detected_language, detected_extension = detect_language(code, path)
    language = args.language or detected_language
    extension = language_to_extension(language) if args.language else detected_extension
    findings, warnings = analyze_code(code, path, language, extension, args)

    return {
        "source": str(path),
        "language": language,
        "findings": findings,
        "warnings": warnings,
    }


def build_report_for_stdin(args):
    code = read_code_from_stdin() if args.stdin else read_code_from_prompt()
    if not code.strip():
        raise ValueError("No code was provided.")

    detected_language, detected_extension = detect_language(code)
    language = args.language or detected_language
    extension = language_to_extension(language) if args.language else detected_extension
    findings, warnings = analyze_code(code, "<stdin>", language, extension, args)

    return {
        "source": "<stdin>",
        "language": language,
        "findings": findings,
        "warnings": warnings,
    }


def print_issue(finding):
    print("=" * 60)
    print(f"Source: {finding['source']}")
    print(f"Tool: {finding['tool']}")
    print(f"Issue: {finding['issue']}")
    print(f"Line: {finding['line']}")
    print(f"Severity: {finding['severity']}")
    print(f"Rule: {finding['rule_id']}")
    print(f"Recommendation: {finding['recommendation']}")
    print("=" * 60)


def print_text_report(report):
    print(f"\n[+] Reviewed {report['scanned_sources']} source(s).")

    visible_file_reports = report["files"][:20]
    for file_report in visible_file_reports:
        print(f"\n[+] Source: {file_report['source']}")
        print(f"[+] Language: {file_report['language']}")
    if len(report["files"]) > len(visible_file_reports):
        hidden_count = len(report["files"]) - len(visible_file_reports)
        print(f"\n[+] ... and {hidden_count} more source(s).")

    for warning in report["warnings"]:
        print(f"[!] {warning}")

    if not report["findings"]:
        print("\n[OK] No major issues found.")
    else:
        print(f"\n[!] Found {len(report['findings'])} issue(s):\n")
        for finding in report["findings"]:
            print_issue(finding)

    if report["summary"]:
        summary_parts = [
            f"{count} {severity.lower()}" for severity, count in report["summary"].items()
        ]
        print(f"\n[+] Summary: {', '.join(summary_parts)}")

    print("\n[+] General secure coding best practices:\n")
    for practice in BEST_PRACTICES:
        print(f"- {practice}")


def build_final_report(file_reports):
    combined_findings = []
    warnings = []
    for file_report in file_reports:
        combined_findings.extend(file_report["findings"])
        warnings.extend(file_report["warnings"])

    findings = dedupe_findings(combined_findings)
    return {
        "files": file_reports,
        "findings": findings,
        "summary": summarize_findings(findings),
        "warnings": warnings,
        "scanned_sources": len(file_reports),
        "best_practices": BEST_PRACTICES,
    }


def determine_exit_code(report):
    if report["findings"]:
        return 1
    if report["warnings"]:
        return 2
    return 0


def main():
    args = parse_args()

    try:
        args = choose_interactive_args(args)
        if args.file or args.path:
            source_paths = gather_sources(args)
            if not source_paths:
                raise ValueError("No supported source files were found.")
            file_reports = [build_report_for_path(path, args) for path in source_paths]
        else:
            file_reports = [build_report_for_stdin(args)]
    except (FileNotFoundError, IsADirectoryError, OSError, ValueError) as exc:
        if args.output == "json":
            print(json.dumps({"error": str(exc)}, indent=2))
        else:
            print(f"[!] {exc}")
        return 2

    report = build_final_report(file_reports)

    if args.output == "json":
        print(json.dumps(report, indent=2))
    else:
        print_text_report(report)

    return determine_exit_code(report)


if __name__ == "__main__":
    sys.exit(main())
