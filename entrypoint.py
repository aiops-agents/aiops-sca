import os
import json
import glob
import re
import sys
import subprocess
import pathlib
import difflib
from typing import List, Dict, Any, Tuple, Optional
from jsonschema import ValidationError
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
    # CSV fallback
    return [p.strip() for p in s.split(",") if p.strip()]

def ensure_dir(path: str):
    pathlib.Path(path).mkdir(parents=True, exist_ok=True)

def fnmatchcase(path: str, pattern: str) -> bool:
    # Convert glob to regex with support for ** and *
    pattern = re.escape(pattern)
    # restore wildcards
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

# ------------- Redaction / audit -------------

SECRET_KEYS = ["KEY", "TOKEN", "PASSWORD", "SECRET"]

def redact_secrets(text: str) -> str:
    if not text:
        return text
    redacted = text
    # Basic heuristic: redact env var values for keys that look sensitive
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

# ------------- Lint parsing -------------

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

# ------------- LLM client -------------

def build_llm_client(provider: str):
    provider = provider.lower()
    if provider == "azure_openai":
        endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
        key = os.getenv("AZURE_OPENAI_API_KEY")
        version = os.getenv("AZURE_OPENAI_API_VERSION")
        if not endpoint or not key or not version:
            gh_print("::error::AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_API_KEY, AZURE_OPENAI_API_VERSION env vars are required for azure_openai")
            sys.exit(1)
        return AzureOpenAI(
            azure_endpoint=endpoint,
            api_key=key,
            api_version=version
        )
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
        # Attempt to extract first top-level JSON object
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
    user_payload = {
        "file_path": file_path,
        "file_content": file_text,
        "issues": issues
    }
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)}
    ]
    try:
        if provider == "azure_openai":
            resp = client.chat.completions.create(
                model=model,  # Azure deployment name
                temperature=temperature,
                max_tokens=max_tokens,
                messages=messages
            )
            content = resp.choices[0].message.content
        else:
            resp = client.chat.completions.create(
                model=model,
                temperature=temperature,
                max_tokens=max_tokens,
                messages=messages
            )
            content = resp.choices[0].message.content

        if audit:
            audit_write(output_dir, file_path, {
                "request": {"messages": messages, "model": model},
                "response_raw": redact_secrets(content or "")
            })

        parsed = parse_json_strict(content or "")
        if not parsed and lint_retry:
            gh_print(f"::notice::Retrying LLM for {file_path} due to invalid JSON.")
            if provider == "azure_openai":
                resp = client.chat.completions.create(
                    model=model,
                    temperature=max(0.1, temperature - 0.1),
                    max_tokens=max_tokens,
                    messages=messages
                )
                content = resp.choices[0].message.content
            else:
                resp = client.chat.completions.create(
                    model=model,
                    temperature=max(0.1, temperature - 0.1),
                    max_tokens=max_tokens,
                    messages=messages
                )
                content = resp.choices[0].message.content

            if audit:
                audit_write(output_dir, file_path, {
                    "request_retry": {"messages": messages, "model": model},
                    "response_raw_retry": redact_secrets(content or "")
                })

            parsed = parse_json_strict(content or "")

        return parsed
    except Exception as e:
        gh_print(f"::warning::LLM call failed for {file_path}: {e}")
        return None

# ------------- Diff and safety -------------

def compute_diff_stats(original: str, new: str) -> Tuple[int, List[str]]:
    orig_lines = original.splitlines(keepends=True)
    new_lines = new.splitlines(keepends=True)
    diff = list(difflib.unified_diff(orig_lines, new_lines, n=3))
    added = sum(1 for l in diff if l.startswith('+') and not l.startswith('+++'))
    removed = sum(1 for l in diff if l.startswith('-') and not l.startswith('---'))
    return (added + removed), diff

# ------------- Git utils -------------

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

# ------------- GitHub PR -------------

def create_pull_request(base_branch: str, head_branch: str, title: str, body: str) -> Optional[str]:
    repo = git_get_repo()
    token = os.getenv("GITHUB_TOKEN") or ""
    if not (repo and token):
        gh_print("::warning::Missing repo or token; cannot create PR.")
        return None
    url = f"https://api.github.com/repos/{repo}/pulls"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json"
    }
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

# ------------- Main -------------

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

    # New inputs
    lint_retry_on_failure = parse_bool(get_input("lint_retry_on_failure", "true"))
    re_lint_after_apply = parse_bool(get_input("re_lint_after_apply", "false"))
    re_lint_cmd = get_input("re_lint_cmd", "")
    re_lint_output_glob = get_input("re_lint_output_glob", "")
    pr_title = get_input("pr_title", "AIOps SCA: Auto-fix Terraform lint issues")
    pr_body = get_input("pr_body", "This PR was opened by AIOps SCA agent to address Terraform static analysis issues.")
    allow_severities = [s.lower() for s in parse_json_or_csv(get_input("allow_severities", '["low","medium","high","critical","warning","error"]'))]
    exclude_rules = set(parse_json_or_csv(get_input("exclude_rules", "[]")))
    max_token_context_bytes = int(get_input("max_token_context_bytes", "0"))
    audit_log = parse_bool(get_input("audit_log", "true"))

    ensure_dir(output_dir)

    # Gather issues
    issues_raw = collect_issues(input_dir, lint_format)
    # Filter by severity and excluded rules
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

    if not issues_by_file:
        gh_print("::notice::No issues found for files in scope. Nothing to do.")
        with open(os.path.join(output_dir, "report.json"), "w", encoding="utf-8") as f:
            json.dump({"summary": "No issues in scope."}, f, indent=2)
        return

    # Initialize LLM client
    client = build_llm_client(llm_provider)

    changed_files: List[str] = []
    recommendations: List[Dict[str, Any]] = []
    per_file_results: Dict[str, Any] = {}
    skipped_large_files: List[str] = []

    # Safety: deny changes in protected paths
    def is_protected(p: str) -> bool:
        posix = pathlib.Path(p).as_posix()
        for patt in protected_paths:
            if fnmatchcase(posix, patt):
                return True
        return False

    # Propose changes per file
    for fp, file_issues in issues_by_file.items():
        if is_protected(fp):
            gh_print(f"::notice::Skipping protected path: {fp}")
            continue
        try:
            with open(fp, "r", encoding="utf-8") as f:
                original = f.read()
        except Exception as e:
            gh_print(f"::warning::Cannot read {fp}: {e}")
            continue

        if max_token_context_bytes and len(original.encode("utf-8")) > max_token_context_bytes:
            gh_print(f"::warning::{fp}: Skipping due to size > max_token_context_bytes={max_token_context_bytes}")
            skipped_large_files.append(fp)
            continue

        resp = llm_propose_new_content(
            client=client,
            provider=llm_provider,
            model=llm_model,
            file_path=fp,
            file_text=original,
            issues=file_issues,
            temperature=temperature,
            max_tokens=max_tokens,
            audit=audit_log,
            output_dir=output_dir,
            lint_retry=lint_retry_on_failure,
        )

        if not resp or "new_content" not in resp:
            gh_print(f"::warning::No valid response for {fp}; skipping.")
            continue

        new_content = resp.get("new_content", "")
        changes_meta = resp.get("changes", [])
        risk_level = resp.get("risk_level", "low")

        # Compute diff & check thresholds
        total_edits, diff_lines = compute_diff_stats(original, new_content)
        per_file_results[fp] = {
            "risk_level": risk_level,
            "total_edits": total_edits,
            "diff": "".join(diff_lines),
            "changes": changes_meta,
        }

        if total_edits == 0:
            gh_print(f"::notice::{fp}: No changes needed.")
            continue

        if len(changed_files) >= max_files_changed:
            gh_print(f"::warning::Change limit reached (max_files_changed={max_files_changed}). Skipping {fp}.")
            continue

        if total_edits > max_lines_changed:
            gh_print(f"::warning::{fp}: Proposed change ({total_edits} lines) exceeds max_lines_changed={max_lines_changed}. Skipping.")
            continue

        # Apply or stage change
        if auto_apply and apply_mode in ("commit", "pr"):
            try:
                with open(fp, "w", encoding="utf-8") as f:
                    f.write(new_content)
                changed_files.append(fp)
                gh_print(f"::notice::{fp}: Changes applied to workspace (not committed yet).")
            except Exception as e:
                gh_print(f"::warning::Failed to write changes for {fp}: {e}")
        else:
            # Write proposed file to output_dir for review
            proposal_path = os.path.join(output_dir, f"{pathlib.Path(fp).name}.proposed.tf")
            with open(proposal_path, "w", encoding="utf-8") as f:
                f.write(new_content)
            gh_print(f"::notice::{fp}: Wrote proposal to {proposal_path}")

        # Recommendation aggregation
        recommendations.append({
            "file_path": fp,
            "risk_level": risk_level,
            "summary": [c.get("explanation", "") for c in changes_meta],
            "severity": [str(c.get("severity", "")).lower() for c in changes_meta],
            "edits": total_edits,
        })

    # Commit/push if needed
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

            # Optional re-lint after apply (requires command)
            re_lint_summary = None
            if re_lint_after_apply and re_lint_cmd.strip():
                try:
                    gh_print(f"::notice::Running re-lint command: {re_lint_cmd}")
                    rl = subprocess.run(re_lint_cmd, shell=True, text=True, capture_output=True)
                    if rl.returncode != 0:
                        gh_print(f"::warning::re_lint_cmd returned {rl.returncode}: {rl.stderr}")
                    else:
                        gh_print(f"::notice::re_lint_cmd stdout: {rl.stdout[:5000]}")
                    if re_lint_output_glob.strip():
                        new_issues = []
                        for path in glob.glob(re_lint_output_glob.strip(), recursive=True):
                            new_issues.extend(normalize_issues_from_file(path, lint_format))
                        re_lint_summary = {"files": len(set([i.get("file_path") for i in new_issues])), "issues": len(new_issues)}
                        gh_print(f"::notice::Re-lint found {re_lint_summary['issues']} issues across {re_lint_summary['files']} files.")
                except Exception as e:
                    gh_print(f"::warning::Re-lint failed: {e}")

            # If apply_mode=pr, attempt to open a PR
            if apply_mode == "pr" and created_branch and created_branch != current_branch:
                pr_url = create_pull_request(base_branch=current_branch, head_branch=created_branch, title=pr_title, body=pr_body)

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
        "pr_url": pr_url
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

    # Fail pipeline if requested and unresolved critical issues still exist
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
