import os
import json
import glob
import re
import sys
import subprocess
import pathlib
import difflib
from typing import List, Dict, Any, Tuple, Optional
import requests

# LLM SDK
try:
    from openai import AzureOpenAI, OpenAI
except Exception as e:
    print(f"::warning::OpenAI SDK not available: {e}")

def gh_print(msg: str):
    print(msg, flush=True)

def get_input(name: str, default: Optional[str] = None, required: bool = False) -> str:
    key = f"INPUT_{name.upper()}"
    val = os.getenv(key)
    if val is None or val == "":
        if required and default is None:
            gh_print(f"::error::Missing required input: {name}")
            sys.exit(1)
        return default if default is not None else ""
    return val

def parse_bool(s: str) -> bool:
    return str(s).strip().lower() in ["1", "true", "yes", "y", "on"]

def parse_json_or_csv(s: str) -> List[str]:
    s = s.strip()
    if s.startswith("["):
        try:
            return json.loads(s)
        except Exception:
            pass
    return [p.strip() for p in s.split(",") if p.strip()]

def ensure_dir(path: str):
    pathlib.Path(path).mkdir(parents=True, exist_ok=True)

def fnmatchcase(path: str, pattern: str) -> bool:
    pattern = re.escape(pattern)
    pattern = pattern.replace(r"\*\*/", r"(.*/)?")
    pattern = pattern.replace(r"\*\*", r".*")
    pattern = pattern.replace(r"\*", r"[^/]*")
    pattern = pattern.replace(r"\?", r".")
    pattern = "^" + pattern + "$"
    return re.match(pattern, path) is not None

def list_tf_files(scope_globs: List[str]) -> List[str]:
    files = set()
    for pattern in scope_globs:
        for f in glob.glob(pattern, recursive=True):
            if os.path.isfile(f) and f.endswith(".tf"):
                files.add(pathlib.Path(f).as_posix())
    return sorted(files)

# --------- Redaction / Audit ---------

SECRET_KEYS = ["KEY", "TOKEN", "PASSWORD", "SECRET"]

def redact_secrets(text: str) -> str:
    if not text:
        return text
    redacted = text
    for k, v in os.environ.items():
        if any(tag in k.upper() for tag in SECRET_KEYS):
            if v and isinstance(v, str) and len(v) >= 6:
                redacted = redacted.replace(v, "[REDACTED]")
    return redacted

def audit_write(output_dir: str, file_path: str, payload: Dict[str, Any]):
    try:
        audit_dir = os.path.join(output_dir, "audit")
        ensure_dir(audit_dir)
        safe_name = pathlib.Path(file_path).name.replace("/", "_")
        out_path = os.path.join(audit_dir, f"{safe_name}.json")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(redact_secrets(json.dumps(payload, indent=2)))
    except Exception as e:
        gh_print(f"::warning::Failed audit write for {file_path}: {e}")

# --------- Lint parsing ---------

def detect_lint_format(payload: Any) -> str:
    if isinstance(payload, dict):
        if "issues" in payload and isinstance(payload["issues"], list):
            return "tflint"
        if "results" in payload and isinstance(payload["results"], list) and any(isinstance(r, dict) and ("rule_id" in r or "rule" in r) for r in payload["results"]):
            return "tfsec"
        if "check_type" in payload and "results" in payload:
            return "checkov"
    return "unknown"

def normalize_issues_from_file(path: str, forced_format: str = "auto") -> List[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except Exception as e:
        gh_print(f"::warning::Failed to parse JSON from {path}: {e}")
        return []

    fmt = detect_lint_format(payload) if forced_format == "auto" else forced_format
    issues = []
    if fmt == "tflint":
        for it in payload.get("issues", []):
            r = it.get("range", {}) or {}
            start = (r.get("start", {}) or {}).get("line", None)
            end = (r.get("end", {}) or {}).get("line", start)
            issues.append({
                "tool": "tflint",
                "rule_id": it.get("rule", ""),
                "message": it.get("message", ""),
                "severity": (it.get("severity", "warning") or "").lower(),
                "file_path": (r.get("filename", "") or "").lstrip("./"),
                "start_line": start,
                "end_line": end,
            })
    elif fmt == "tfsec":
        for res in payload.get("results", []):
            loc = res.get("location", {}) or {}
            start = loc.get("start_line", None)
            end = loc.get("end_line", start)
            issues.append({
                "tool": "tfsec",
                "rule_id": res.get("rule_id", ""),
                "message": res.get("description", ""),
                "severity": (res.get("severity", "medium") or "").lower(),
                "file_path": (loc.get("filename", "") or "").lstrip("./"),
                "start_line": start,
                "end_line": end,
                "resolution": res.get("resolution", ""),
                "impact": res.get("impact", ""),
            })
    elif fmt == "checkov":
        res = payload.get("results", {}) or {}
        for fc in res.get("failed_checks", []):
            rng = fc.get("file_line_range")
            start, end = None, None
            if isinstance(rng, list) and len(rng) == 2:
                start, end = rng
            issues.append({
                "tool": "checkov",
                "rule_id": fc.get("check_id", ""),
                "message": fc.get("check_name", ""),
                "severity": (fc.get("severity", "medium") or "").lower(),
                "file_path": (fc.get("file_path", "") or "").lstrip("./"),
                "start_line": start,
                "end_line": end,
                "guideline": fc.get("guideline", ""),
            })
    else:
        gh_print(f"::notice::Unknown lint format in {path}. Skipping.")
    return issues

def collect_issues(input_dir: str, lint_format: str) -> List[Dict[str, Any]]:
    issues = []
    for path in glob.glob(os.path.join(input_dir, "**/*.json"), recursive=True):
        issues.extend(normalize_issues_from_file(path, lint_format))
    return issues

# --------- LLM client ---------

def build_llm_client(provider: str):
    provider = provider.lower()
    if provider == "azure_openai":
        endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
        key = os.getenv("AZURE_OPENAI_API_KEY")
        version = os.getenv("AZURE_OPENAI_API_VERSION")
        if not endpoint or not key or not version:
            gh_print("::error::AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_API_KEY, AZURE_OPENAI_API_VERSION env vars are required for azure_openai")
            sys.exit(1)
        return AzureOpenAI(azure_endpoint=endpoint, api_key=key, api_version=version)
    elif provider == "openai":
        key = os.getenv("OPENAI_API_KEY")
        if not key:
            gh_print("::error::OPENAI_API_KEY env var is required for openai provider")
            sys.exit(1)
        return OpenAI(api_key=key)
    else:
        gh_print(f"::error::Unsupported llm_provider: {provider}")
        sys.exit(1)

SYSTEM_PROMPT = """You are a principal DevOps/Terraform engineer and static analysis expert.
- Goal: Given a Terraform file and lint issues, produce the minimal, safe corrections that resolve the issues without altering intent.
- Preserve variables, provider versions, and module behavior. No destructive changes.
- Respect the user's guardrails and ONLY change content inside the provided file content.
- Only touch what's necessary; avoid broad refactors.
- If an issue is subjective or risky, prefer a small recommendation rather than invasive edits.

Output strict JSON with this schema:
{
  "file_path": "<string>",
  "risk_level": "low|medium|high",
  "changes": [
    {
      "rule_id": "<string>",
      "explanation": "<string concise>",
      "severity": "<string>"
    }
  ],
  "new_content": "<entire corrected file content>"
}
No markdown, no comments outside JSON.
"""

def parse_json_strict(s: str) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(s)
    except Exception:
        start = s.find("{")
        end = s.rfind("}")
        if start != -1 and end != -1 and end > start:
            candidate = s[start:end+1]
            try:
                return json.loads(candidate)
            except Exception:
                return None
        return None

def llm_propose_new_content(client, provider: str, model: str, file_path: str, file_text: str, issues: List[Dict[str, Any]], temperature: float, max_tokens: int, audit: bool, output_dir: str, lint_retry: bool) -> Optional[Dict[str, Any]]:
    user_payload = {"file_path": file_path, "file_content": file_text, "issues": issues}
    messages = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)}]
    try:
        if provider == "azure_openai":
            resp = client.chat.completions.create(model=model, temperature=temperature, max_tokens=max_tokens, messages=messages)
            content = resp.choices[0].message.content
        else:
            resp = client.chat_completions.create(model=model, temperature=temperature, max_tokens=max_tokens, messages=messages) if hasattr(client, "chat_completions") else client.chat.completions.create(model=model, temperature=temperature, max_tokens=max_tokens, messages=messages)
            content = resp.choices[0].message.content

        if audit:
            audit_write(output_dir, file_path, {"request": {"messages": messages, "model": model}, "response_raw": redact_secrets(content or "")})

        parsed = parse_json_strict(content or "")
        if not parsed and lint_retry:
            gh_print(f"::notice::Retrying LLM for {file_path} due to invalid JSON.")
            if provider == "azure_openai":
                resp = client.chat.completions.create(model=model, temperature=max(0.1, temperature - 0.1), max_tokens=max_tokens, messages=messages)
                content = resp.choices[0].message.content
            else:
                resp = client.chat.completions.create(model=model, temperature=max(0.1, temperature - 0.1), max_tokens=max_tokens, messages=messages)
                content = resp.choices[0].message.content
            if audit:
                audit_write(output_dir, file_path, {"request_retry": {"messages": messages, "model": model}, "response_raw_retry": redact_secrets(content or "")})
            parsed = parse_json_strict(content or "")
        return parsed
    except Exception as e:
        gh_print(f"::warning::LLM call failed for {file_path}: {e}")
        return None

# --------- Diff, patches, safety ---------

def make_unified_patch(original: str, new: str, file_path: str) -> Tuple[int, str]:
    orig_lines = original.splitlines(keepends=True)
    new_lines = new.splitlines(keepends=True)
    diff = list(difflib.unified_diff(orig_lines, new_lines, fromfile=file_path, tofile=file_path, n=3))
    added = sum(1 for l in diff if l.startswith('+') and not l.startswith('+++'))
    removed = sum(1 for l in diff if l.startswith('-') and not l.startswith('---'))
    total_edits = added + removed
    return total_edits, "".join(diff)

def write_patch(patches_dir: str, file_path: str, patch_text: str) -> str:
    ensure_dir(patches_dir)
    name = pathlib.Path(file_path).name + ".patch"
    out_path = os.path.join(patches_dir, name)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(patch_text)
    return out_path

# --------- Git utils ---------

def git_run(args: List[str], check=True):
    return subprocess.run(args, check=check, text=True, capture_output=True)

def git_setup_user(name: str, email: str):
    git_run(["git", "config", "--global", "user.name", name])
    git_run(["git", "config", "--global", "user.email", email])

def git_get_repo() -> str:
    return os.getenv("GITHUB_REPOSITORY", "")

def git_prepare_remote_with_token():
    token = os.getenv("GITHUB_TOKEN") or os.getenv("TOKEN")
    repo = git_get_repo()
    if not token or not repo:
        return
    url = f"https://x-access-token:{token}@github.com/{repo}.git"
    try:
        git_run(["git", "remote", "set-url", "origin", url])
    except Exception as e:
        gh_print(f"::warning::Failed to set remote url: {e}")

def git_current_branch() -> str:
    r = git_run(["git", "rev-parse", "--abbrev-ref", "HEAD"])
    return r.stdout.strip()

def git_create_branch(branch: str):
    git_run(["git", "checkout", "-b", branch])

def git_add(paths: List[str]):
    if paths:
        git_run(["git", "add"] + paths)

def git_commit(message: str) -> Optional[str]:
    try:
        git_run(["git", "commit", "-m", message])
        r = git_run(["git", "rev-parse", "HEAD"])
        return r.stdout.strip()
    except subprocess.CalledProcessError as e:
        combined = (e.stdout or "") + (e.stderr or "")
        if "nothing to commit" in combined.lower():
            gh_print("::notice::No changes to commit.")
            return None
        raise

def git_push(branch: str):
    git_run(["git", "push", "origin", branch])

# --------- GitHub PR ---------

def create_pull_request(base_branch: str, head_branch: str, title: str, body: str) -> Optional[str]:
    repo = git_get_repo()
    token = os.getenv("GITHUB_TOKEN") or ""
    if not (repo and token):
        gh_print("::warning::Missing repo or token; cannot create PR.")
        return None
    url = f"https://api.github.com/repos/{repo}/pulls"
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}
    data = {"title": title, "head": head_branch, "base": base_branch, "body": body, "maintainer_can_modify": True}
    try:
        resp = requests.post(url, headers=headers, json=data, timeout=30)
        if resp.status_code == 201:
            pr = resp.json()
            gh_print(f"::notice::Opened PR #{pr.get('number')} -> {pr.get('html_url')}")
            return pr.get("html_url")
        else:
            msg = resp.text
            if "A pull request already exists" in msg or resp.status_code == 422:
                gh_print("::notice::PR already exists or cannot be created (422).")
                return None
            gh_print(f"::warning::Failed to create PR: {resp.status_code} {msg}")
            return None
    except Exception as e:
        gh_print(f"::warning::PR creation failed: {e}")
        return None

# --------- SARIF utilities ---------

def sev_to_sarif_level(sev: str) -> str:
    s = (sev or "").lower()
    if s in ("critical", "high", "error"):
        return "error"
    if s in ("medium", "warning"):
        return "warning"
    return "note"

def issues_to_sarif(issues: List[Dict[str, Any]], run_name: str = "aiops-sca") -> Dict[str, Any]:
    rules_index: Dict[str, int] = {}
    rules: List[Dict[str, Any]] = []
    results: List[Dict[str, Any]] = []

    def rule_for(rule_id: str, tool: str, message: str) -> int:
        rid = f"{tool}:{rule_id}" if rule_id else f"{tool}:unknown"
        if rid in rules_index:
            return rules_index[rid]
        idx = len(rules)
        rules_index[rid] = idx
        rules.append({
            "id": rid,
            "name": rule_id or "unknown",
            "shortDescription": {"text": f"{tool} {rule_id}".strip()},
            "fullDescription": {"text": message or f"{tool} rule {rule_id}".strip()},
            "help": {"text": message or "", "markdown": message or ""},
        })
        return idx

    for it in issues:
        rule_idx = rule_for(it.get("rule_id", ""), it.get("tool", "lint"), it.get("message", ""))
        path = (it.get("file_path") or "").replace("\\", "/")
        start = it.get("start_line") or 1
        end = it.get("end_line") or start
        results.append({
            "ruleId": rules[rule_idx]["id"],
            "level": sev_to_sarif_level(it.get("severity", "")),
            "message": {"text": it.get("message", "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": path},
                    "region": {"startLine": start, "endLine": end}
                }
            }]
        })

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": run_name, "informationUri": "https://github.com/ai-agents/aiops-sca", "rules": rules}},
            "results": results
        }]
    }
    return sarif

def tool_split_issues(issues: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    by_tool: Dict[str, List[Dict[str, Any]]] = {"tflint": [], "tfsec": [], "checkov": []}
    for it in issues:
        t = (it.get("tool") or "").lower()
        if t in by_tool:
            by_tool[t].append(it)
    return by_tool

def write_tool_sarif_convert(issues: List[Dict[str, Any]], out_dir: str, suffix: str = ""):
    ensure_dir(out_dir)
    split = tool_split_issues(issues)
    for tool, tool_issues in split.items():
        if not tool_issues:
            continue
        sarif = issues_to_sarif(tool_issues, run_name=f"aiops-sca-{tool}{('-'+suffix) if suffix else ''}")
        path = os.path.join(out_dir, f"{tool}.sarif")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2)
        gh_print(f"::notice::Wrote converted SARIF for {tool} -> {path}")

def copy_if_exists(src: str, dst: str) -> bool:
    try:
        if os.path.isfile(src):
            ensure_dir(pathlib.Path(dst).parent.as_posix())
            with open(src, "rb") as s, open(dst, "wb") as d:
                d.write(s.read())
            return True
    except Exception as e:
        gh_print(f"::warning::Failed to copy {src} -> {dst}: {e}")
    return False

# --------- Built-in re-lint (JSON + optional native SARIF) ---------

def run_cmd(cmd: str) -> Tuple[int, str, str]:
    p = subprocess.run(cmd, shell=True, text=True, capture_output=True)
    return p.returncode, p.stdout, p.stderr

def run_builtin_relint(tools: List[str], output_dir: str, generate_native_sarif: bool, tool_sarif_post_dir: str) -> Dict[str, Any]:
    relint_dir = os.path.join(output_dir, "re_lint")
    ensure_dir(relint_dir)
    issues_all: List[Dict[str, Any]] = []

    # TFLint JSON
    if "tflint" in tools:
        run_cmd(f"tflint --recursive --format json > {relint_dir}/tflint.json || true")
        issues_all += normalize_issues_from_file(os.path.join(relint_dir, "tflint.json"), "tflint")
        if generate_native_sarif:
            # Try native SARIF; not all versions support it, fallback okay
            code, _, err = run_cmd(f"tflint --recursive --format sarif > {pathlib.Path(tool_sarif_post_dir, 'tflint.sarif')} || true")
            if code != 0 and err:
                gh_print(f"::notice::tflint native SARIF may not be supported in this version; falling back to converted SARIF later.")

    # tfsec JSON
    if "tfsec" in tools:
        run_cmd(f"tfsec --format json --out {relint_dir}/tfsec.json || true")
        issues_all += normalize_issues_from_file(os.path.join(relint_dir, "tfsec.json"), "tfsec")
        if generate_native_sarif:
            run_cmd(f"tfsec --format sarif --out {pathlib.Path(tool_sarif_post_dir, 'tfsec.sarif')} || true")

    # Checkov JSON
    if "checkov" in tools:
        run_cmd(f"checkov -d . -o json --output-file-path {relint_dir}/checkov.json || true")
        if os.path.isfile(os.path.join(relint_dir, "checkov.json")):
            issues_all += normalize_issues_from_file(os.path.join(relint_dir, "checkov.json"), "checkov")
        else:
            for p in glob.glob(os.path.join(relint_dir, "**/*.json"), recursive=True):
                issues_all += normalize_issues_from_file(p, "checkov")
        if generate_native_sarif:
            run_cmd(f"checkov -d . -o sarif --output-file-path {pathlib.Path(tool_sarif_post_dir, 'checkov.sarif')} || true")

    files = set([i.get("file_path") for i in issues_all if i.get("file_path")])
    return {"issues": len(issues_all), "files": len(files), "collected_issues": issues_all}

# --------- Main ---------

def main():
    enable = parse_bool(get_input("enable", "true"))
    if not enable:
        gh_print("::notice::Agent disabled (enable=false). Exiting.")
        return

    scope = parse_json_or_csv(get_input("scope", '["**/*.tf"]', required=True))
    input_dir = get_input("input_dir", "./input")
    output_dir = get_input("output_dir", "./output")
    llm_provider = get_input("llm_provider", "azure_openai")
    llm_model = get_input("llm_model", required=True)
    show_recommendation = parse_bool(get_input("show_recommendation", "true"))
    auto_apply = parse_bool(get_input("auto_apply", "false"))
    lint_format = get_input("lint_format", "auto")
    apply_mode = get_input("apply_mode", "commit")
    max_lines_changed = int(get_input("max_lines_changed", "200"))
    max_files_changed = int(get_input("max_files_changed", "10"))
    protected_paths = parse_json_or_csv(get_input("protected_paths", "[]"))
    recommendation_format = get_input("recommendation_format", "markdown")
    fail_on_unfixed = parse_bool(get_input("fail_on_unfixed", "false"))
    commit_message_prefix = get_input("commit_message_prefix", "[aiops-sca]")
    git_user_name = get_input("git_user_name", "aiops-sca[bot]")
    git_user_email = get_input("git_user_email", "aiops-sca-bot@example.com")
    temperature = float(get_input("temperature", "0.2"))
    max_tokens = int(get_input("max_tokens", "4000"))

    lint_retry_on_failure = parse_bool(get_input("lint_retry_on_failure", "true"))
    allow_severities = [s.lower() for s in parse_json_or_csv(get_input("allow_severities", '["low","medium","high","critical","warning","error"]'))]
    exclude_rules = set(parse_json_or_csv(get_input("exclude_rules", "[]")))
    max_token_context_bytes = int(get_input("max_token_context_bytes", "0"))
    audit_log = parse_bool(get_input("audit_log", "true"))

    # SARIF (aggregated)
    sarif_output_enabled = parse_bool(get_input("sarif_output_enabled", "true"))
    sarif_pre_path = get_input("sarif_pre_path", "output/aiops-sca.sarif")
    sarif_post_path = get_input("sarif_post_path", "output/aiops-sca-post.sarif")

    # Tool-specific SARIF
    tool_sarif_enabled = parse_bool(get_input("tool_sarif_enabled", "true"))
    tool_sarif_mode = get_input("tool_sarif_mode", "convert").lower()  # pre-fix
    tool_sarif_dir = get_input("tool_sarif_dir", "output/sarif")
    tool_sarif_post_mode = get_input("tool_sarif_post_mode", "native").lower()
    tool_sarif_post_dir = get_input("tool_sarif_post_dir", "output/sarif-post")

    # Re-lint
    re_lint_after_apply = parse_bool(get_input("re_lint_after_apply", "false"))
    re_lint_tooling = get_input("re_lint_tooling", "built-in").lower()
    re_lint_tools = [t.strip().lower() for t in parse_json_or_csv(get_input("re_lint_tools", '["tflint","tfsec","checkov"]'))]
    re_lint_cmd = get_input("re_lint_cmd", "")
    re_lint_output_glob = get_input("re_lint_output_glob", "")

    # Patches
    patches_enabled = parse_bool(get_input("patches_enabled", "true"))
    patches_dir = get_input("patches_dir", "output/patches")
    combined_patch_name = get_input("combined_patch_name", "changes.patch")

    ensure_dir(output_dir)

    # Gather initial issues
    issues_raw = collect_issues(input_dir, lint_format)
    issues = []
    for it in issues_raw:
        sev = (it.get("severity") or "").lower()
        if allow_severities and sev and sev not in allow_severities:
            continue
        if it.get("rule_id") in exclude_rules:
            continue
        issues.append(it)

    gh_print(f"::notice::Collected {len(issues)} eligible lint issues from {input_dir} (filtered from {len(issues_raw)})")

    files_in_scope = list_tf_files(scope)
    files_in_scope_set = set(files_in_scope)

    # Index issues by file (only files in scope)
    issues_by_file: Dict[str, List[Dict[str, Any]]] = {}
    for it in issues:
        fp = (it.get("file_path") or "").lstrip("./")
        if fp in files_in_scope_set:
            issues_by_file.setdefault(fp, []).append(it)

    # Aggregated SARIF pre-fix
    if sarif_output_enabled:
        pre = issues_to_sarif(issues)
        pre_path = pathlib.Path(sarif_pre_path); ensure_dir(str(pre_path.parent))
        with open(sarif_pre_path, "w", encoding="utf-8") as f:
            json.dump(pre, f, indent=2)
        gh_print(f"::notice::Wrote SARIF pre-fix to {sarif_pre_path}")

    # Tool-specific SARIF pre-fix
    if tool_sarif_enabled:
        ensure_dir(tool_sarif_dir)
        if tool_sarif_mode == "native":
            # Attempt to copy native SARIF produced by previous steps; fallback to convert
            found = False
            mapping = {"tflint": ["tflint.sarif"], "tfsec": ["tfsec.sarif"], "checkov": ["checkov.sarif"]}
            for tool, names in mapping.items():
                copied = False
                for name in names:
                    if copy_if_exists(os.path.join(input_dir, name), os.path.join(tool_sarif_dir, f"{tool}.sarif")):
                        gh_print(f"::notice::Copied native SARIF for {tool} -> {os.path.join(tool_sarif_dir, f'{tool}.sarif')}")
                        copied = True; found = True; break
                if not copied:
                    gh_print(f"::notice::Native SARIF for {tool} not found in {input_dir}; will convert.")
            # Convert for any not present
            write_tool_sarif_convert(issues, tool_sarif_dir, suffix="pre")
        else:
            write_tool_sarif_convert(issues, tool_sarif_dir, suffix="pre")

    if not issues_by_file:
        gh_print("::notice::No issues found for files in scope. Nothing to do.")
        with open(os.path.join(output_dir, "report.json"), "w", encoding="utf-8") as f:
            json.dump({"summary": "No issues in scope."}, f, indent=2)
        return

    # Initialize LLM
    client = build_llm_client(llm_provider)

    changed_files: List[str] = []
    recommendations: List[Dict[str, Any]] = []
    per_file_results: Dict[str, Any] = {}
    skipped_large_files: List[str] = []
    combined_patches: List[str] = []

    # Fix plan scaffold
    fix_plan: Dict[str, Any] = {
        "summary": {"files_considered": len(issues_by_file), "files_applied": 0, "files_skipped": 0},
        "entries": []
    }

    def is_protected(p: str) -> bool:
        posix = pathlib.Path(p).as_posix()
        for patt in protected_paths:
            if fnmatchcase(posix, patt):
                return True
        return False

    # Propose & possibly apply per file
    for fp, file_issues in issues_by_file.items():
        entry = {"file_path": fp, "status": "skipped", "reason": "", "risk_level": None, "total_edits": 0, "changes": [], "diff": "", "patch_path": ""}
        if is_protected(fp):
            entry["reason"] = "protected_path"
            fix_plan["entries"].append(entry)
            gh_print(f"::notice::Skipping protected path: {fp}")
            continue
        try:
            with open(fp, "r", encoding="utf-8") as f:
                original = f.read()
        except Exception as e:
            entry["reason"] = f"read_error: {e}"
            fix_plan["entries"].append(entry)
            gh_print(f"::warning::Cannot read {fp}: {e}")
            continue

        if max_token_context_bytes and len(original.encode("utf-8")) > max_token_context_bytes:
            entry["reason"] = f"file_too_large>{max_token_context_bytes}"
            skipped_large_files.append(fp)
            fix_plan["entries"].append(entry)
            gh_print(f"::warning::{fp}: Skipping due to size > max_token_context_bytes={max_token_context_bytes}")
            continue

        resp = llm_propose_new_content(
            client=client, provider=llm_provider, model=llm_model,
            file_path=fp, file_text=original, issues=file_issues,
            temperature=temperature, max_tokens=max_tokens,
            audit=audit_log, output_dir=output_dir, lint_retry=lint_retry_on_failure,
        )

        if not resp or "new_content" not in resp:
            entry["reason"] = "llm_no_valid_response"
            fix_plan["entries"].append(entry)
            gh_print(f"::warning::No valid response for {fp}; skipping.")
            continue

        new_content = resp.get("new_content", "")
        changes_meta = resp.get("changes", [])
        risk_level = resp.get("risk_level", "low")

        total_edits, patch_text = make_unified_patch(original, new_content, fp)

        per_file_results[fp] = {"risk_level": risk_level, "total_edits": total_edits, "changes": changes_meta}
        entry["risk_level"] = risk_level
        entry["total_edits"] = total_edits
        entry["changes"] = changes_meta
        entry["diff"] = patch_text

        if total_edits == 0:
            entry["status"] = "no_change_needed"
            fix_plan["entries"].append(entry)
            gh_print(f"::notice::{fp}: No changes needed.")
            continue

        if len(changed_files) >= max_files_changed:
            entry["reason"] = "max_files_changed_limit"
            fix_plan["entries"].append(entry)
            gh_print(f"::warning::Change limit reached (max_files_changed={max_files_changed}). Skipping {fp}.")
            continue

        if total_edits > max_lines_changed:
            entry["reason"] = "max_lines_changed_limit"
            fix_plan["entries"].append(entry)
            gh_print(f"::warning::{fp}: Proposed change ({total_edits} lines) exceeds max_lines_changed={max_lines_changed}. Skipping.")
            continue

        # Write per-file patch (applied or proposed)
        patch_path = ""
        if patches_enabled:
            patch_path = write_patch(patches_dir, fp, patch_text)
            combined_patches.append(patch_text)
            entry["patch_path"] = patch_path

        # Apply or propose
        if auto_apply and apply_mode in ("commit", "pr"):
            try:
                with open(fp, "w", encoding="utf-8") as f:
                    f.write(new_content)
                changed_files.append(fp)
                entry["status"] = "applied"
                fix_plan["summary"]["files_applied"] += 1
                gh_print(f"::notice::{fp}: Changes applied to workspace (not committed yet).")
            except Exception as e:
                entry["reason"] = f"write_failed: {e}"
                fix_plan["entries"].append(entry)
                gh_print(f"::warning::Failed to write changes for {fp}: {e}")
                continue
        else:
            # Save proposed file for review
            proposal_path = os.path.join(output_dir, f"{pathlib.Path(fp).name}.proposed.tf")
            with open(proposal_path, "w", encoding="utf-8") as f:
                f.write(new_content)
            entry["status"] = "proposed"
            fix_plan["summary"]["files_skipped"] += 1
            gh_print(f"::notice::{fp}: Wrote proposal to {proposal_path}")

        recommendations.append({
            "file_path": fp,
            "risk_level": risk_level,
            "summary": [c.get("explanation", "") for c in changes_meta],
            "severity": [str(c.get("severity", "")).lower() for c in changes_meta],
            "edits": total_edits,
        })

        fix_plan["entries"].append(entry)

    # Combined patch file
    if patches_enabled and combined_patches:
        ensure_dir(patches_dir)
        combined_path = os.path.join(patches_dir, combined_patch_name)
        with open(combined_path, "w", encoding="utf-8") as f:
            f.write("\n".join(combined_patches))
        gh_print(f"::notice::Wrote combined patch -> {combined_path}")

    # Commit/push & optional PR
    commit_sha = None
    created_branch = None
    pr_url = None

    if auto_apply and changed_files:
        git_setup_user(git_user_name, git_user_email)
        git_prepare_remote_with_token()
        current_branch = git_current_branch()

        if apply_mode == "pr":
            created_branch = f"aiops-sca/{current_branch}"
            try:
                git_create_branch(created_branch)
            except Exception as e:
                gh_print(f"::warning::Failed to create branch {created_branch}, attempting to continue on current branch. {e}")
                created_branch = current_branch

        git_add(changed_files)
        msg = f"{commit_message_prefix} Auto-fix Terraform lint issues in {len(changed_files)} file(s)"
        commit_sha = git_commit(msg)
        if commit_sha:
            target_branch = created_branch or current_branch
            try:
                git_push(target_branch)
                gh_print(f"::notice::Pushed changes to {target_branch} ({commit_sha})")
            except Exception as e:
                gh_print(f"::error::Failed to push changes: {e}")
            if apply_mode == "pr" and created_branch and created_branch != current_branch:
                pr_url = create_pull_request(base_branch=current_branch, head_branch=created_branch, title="AIOps SCA: Auto-fix Terraform lint issues", body="This PR was opened by AIOps SCA agent to address Terraform static analysis issues.")

    # Re-lint
    relint_summary = None
    if re_lint_after_apply:
        if re_lint_tooling == "built-in":
            ensure_dir(tool_sarif_post_dir)
            generate_native_sarif = (tool_sarif_post_mode == "native")
            relint_summary = run_builtin_relint(re_lint_tools, output_dir, generate_native_sarif, tool_sarif_post_dir)
            # For any tool SARIF not produced natively, convert from collected issues
            if tool_sarif_enabled:
                # Check which SARIF files exist; convert missing ones
                split = tool_split_issues(relint_summary["collected_issues"])
                for tool in ["tflint", "tfsec", "checkov"]:
                    dest = os.path.join(tool_sarif_post_dir, f"{tool}.sarif")
                    if not os.path.isfile(dest):
                        if split.get(tool):
                            sarif = issues_to_sarif(split[tool], run_name=f"aiops-sca-{tool}-post")
                            with open(dest, "w", encoding="utf-8") as f:
                                json.dump(sarif, f, indent=2)
                            gh_print(f"::notice::Wrote converted post-fix SARIF for {tool} -> {dest}")
        else:
            if re_lint_cmd.strip():
                code, out, err = run_cmd(re_lint_cmd)
                if code != 0 and err:
                    gh_print(f"::warning::re_lint_cmd exit {code}: {err}")
                new_issues = []
                if re_lint_output_glob.strip():
                    for path in glob.glob(re_lint_output_glob.strip(), recursive=True):
                        new_issues.extend(normalize_issues_from_file(path, lint_format))
                relint_summary = {"issues": len(new_issues), "files": len(set([i.get("file_path") for i in new_issues if i.get("file_path")])), "collected_issues": new_issues}
                # Convert per-tool SARIF post-fix if enabled
                if tool_sarif_enabled:
                    write_tool_sarif_convert(new_issues, tool_sarif_post_dir, suffix="post")
            else:
                gh_print("::warning::re_lint_tooling=custom but no re_lint_cmd provided; skipping re-lint.")

    # Aggregated SARIF post-fix
    if sarif_output_enabled and relint_summary and isinstance(relint_summary.get("collected_issues"), list):
        post = issues_to_sarif(relint_summary["collected_issues"])
        post_path = pathlib.Path(sarif_post_path); ensure_dir(str(post_path.parent))
        with open(sarif_post_path, "w", encoding="utf-8") as f:
            json.dump(post, f, indent=2)
        gh_print(f"::notice::Wrote SARIF post-fix to {sarif_post_path}")

    # Write outputs
    report = {
        "files_in_scope": files_in_scope,
        "issues_considered": len(issues),
        "files_changed": changed_files,
        "skipped_large_files": skipped_large_files,
        "per_file_results": per_file_results,
        "commit_sha": commit_sha,
        "apply_mode": apply_mode,
        "auto_apply": auto_apply,
        "pr_url": pr_url,
        "re_lint": relint_summary if relint_summary else None,
        "patches_dir": patches_dir if patches_enabled else None
    }
    with open(os.path.join(output_dir, "report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    if show_recommendation:
        if recommendation_format == "json":
            with open(os.path.join(output_dir, "recommendations.json"), "w", encoding="utf-8") as f:
                json.dump(recommendations, f, indent=2)
        else:
            md = ["# AIOps SCA Recommendations"]
            for rec in recommendations:
                md.append(f"## {rec['file_path']}")
                md.append(f"- Risk: {rec['risk_level']}")
                md.append(f"- Estimated edits: {rec['edits']}")
                if rec.get("summary"):
                    md.append("- Changes:")
                    for s in rec["summary"]:
                        if s:
                            md.append(f"  - {s}")
            with open(os.path.join(output_dir, "recommendations.md"), "w", encoding="utf-8") as f:
                f.write("\n".join(md))

    # Fix plan
    with open(os.path.join(output_dir, "fix_plan.json"), "w", encoding="utf-8") as f:
        json.dump(fix_plan, f, indent=2)
    # Optional Markdown
    lines = ["# AIOps SCA Fix Plan", f"- Files considered: {fix_plan['summary']['files_considered']}", f"- Files applied: {fix_plan['summary']['files_applied']}", f"- Files skipped: {fix_plan['summary']['files_skipped']}"]
    for e in fix_plan["entries"]:
        lines.append(f"## {e['file_path']}")
        lines.append(f"- Status: {e['status']}")
        if e.get("reason"): lines.append(f"- Reason: {e['reason']}")
        if e.get("risk_level"): lines.append(f"- Risk: {e['risk_level']}")
        lines.append(f"- Estimated edits: {e.get('total_edits', 0)}")
        if e.get("patch_path"): lines.append(f"- Patch: {e['patch_path']}")
        if e.get("changes"):
            lines.append("- Changes:")
            for c in e["changes"]:
                lines.append(f"  - [{c.get('severity','')}] {c.get('rule_id','')}: {c.get('explanation','')}")
    with open(os.path.join(output_dir, "fix_plan.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    # Fail if requested
    if fail_on_unfixed:
        unresolved_crit = 0
        for fp, res in per_file_results.items():
            if res.get("total_edits", 0) == 0 and len(issues_by_file.get(fp, [])) > 0:
                severities = [str(i.get("severity", "")).lower() for i in issues_by_file.get(fp, [])]
                if any(s in ("high", "critical", "error") for s in severities):
                    unresolved_crit += 1
        if unresolved_crit > 0:
            gh_print(f"::error::{unresolved_crit} unresolved critical/high issues remain.")
            sys.exit(2)

if __name__ == "__main__":
    main()
