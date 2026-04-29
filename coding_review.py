import subprocess
import tempfile
import json

print("Paste your code (ANY language). Press CTRL+D+Enter (Linux/Mac) or CTRL+Z+Enter (Windows) to finish:\n")

# Read input
code = ""
try:
    while True:
        code += input() + "\n"
except EOFError:
    pass


def detect_language(code):
    if "import " in code and "def " in code:
        return "python", ".py"
    elif "console.log" in code or "function" in code:
        return "javascript", ".js"
    elif "public class" in code:
        return "java", ".java"
    elif "#include" in code:
        return "c", ".c"
    return "unknown", ".txt"


def get_recommendation(issue_text):
    issue_text = issue_text.lower()

    if "eval" in issue_text:
        return "Avoid eval(). Use safer parsing or predefined logic."
    elif "exec" in issue_text:
        return "Avoid exec(). It allows arbitrary code execution."
    elif "subprocess" in issue_text or "shell=true" in issue_text:
        return "Avoid shell=True. Use subprocess with list arguments."
    elif "sql" in issue_text:
        return "Use parameterized queries to prevent SQL Injection."
    elif "pickle" in issue_text:
        return "Avoid untrusted pickle data. Use JSON instead."
    elif "hardcoded" in issue_text or "password" in issue_text:
        return "Do not store secrets in code. Use environment variables."
    else:
        return "Follow secure coding practices and validate inputs."


lang, ext = detect_language(code)

# Save to temp file
with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as temp:
    temp.write(code.encode())
    temp_path = temp.name

print(f"\n[+] Detected language: {lang}")
print("[+] Running Semgrep...\n")

# Run Semgrep JSON output
semgrep_proc = subprocess.run(
    ["semgrep", "--config=auto", "--json", temp_path],
    capture_output=True,
    text=True
)

try:
    semgrep_data = json.loads(semgrep_proc.stdout)
    results = semgrep_data.get("results", [])

    if not results:
        print("[✓] No major issues found by Semgrep\n")
    else:
        print(f"[!] Found {len(results)} issues:\n")

        for r in results:
            print("=" * 60)
            print(f"Issue: {r['extra']['message']}")
            print(f"Line: {r['start']['line']}")
            print(f"Severity: {r['extra'].get('severity', 'N/A')}")

            recommendation = get_recommendation(r['extra']['message'])
            print(f"💡 Recommendation: {recommendation}")
            print("=" * 60)

except:
    print("[!] Could not parse Semgrep output")

if lang == "python":
    print("\n[+] Running Bandit...\n")

    bandit_proc = subprocess.run(
        ["bandit", "-f", "json", temp_path],
        capture_output=True,
        text=True
    )

    try:
        bandit_data = json.loads(bandit_proc.stdout)
        issues = bandit_data.get("results", [])

        for i in issues:
            print("=" * 60)
            print(f"Issue: {i['issue_text']}")
            print(f"Line: {i['line_number']}")
            print(f"Severity: {i['issue_severity']}")

            recommendation = get_recommendation(i['issue_text'])
            print(f"💡 Recommendation: {recommendation}")
            print("=" * 60)

    except:
        print("[!] Could not parse Bandit output")


print("\n🔐 GENERAL SECURE CODING BEST PRACTICES:\n")

best_practices = [
    "✔ Validate and sanitize all user inputs",
    "✔ Avoid hardcoded secrets (use environment variables)",
    "✔ Use parameterized queries for database operations",
    "✔ Avoid unsafe functions like eval(), exec()",
    "✔ Keep dependencies updated",
    "✔ Use proper authentication & authorization",
    "✔ Follow least privilege principle",
]

for bp in best_practices:
    print(bp)