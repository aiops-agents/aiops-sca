# Open Source Project
## **Static Code Analysis (SCA) AI Agent for Infrastructure-as-Code**

**Status:** Testing in-progress. If you have any queries, please reach out to @TheSolutionArchitect.

**Release v1.0.0:** AIOps Static Code Analysis Agent; **Objective:** "Agentic AI to analyze Terraform lint outputs and optionally auto-fix and push changes"


**Usage:** Please [refer here](https://github.com/aiops-agents/aiops-gh-workflows) for the GitHub workflow usage. 
```
- name: AIOps SCA Agent
  uses: ai-agents/aiops-sca@v1
  with:
    enable: true
    scope: '["infra/**/*.tf"]'
    input_dir: "./input"
    output_dir: "./output"
    llm_provider: "azure_openai"
    llm_model: "gpt-4o-mini"
    show_recommendation: true
    auto_apply: true
    lint_format: "auto"
    apply_mode: "pr"                # open a PR with changes
    pr_title: "AIOps SCA: Terraform fixes"
    pr_body: "Automated changes by AIOps SCA. Please review."
    max_lines_changed: "200"
    max_files_changed: "10"
    protected_paths: '["infra/modules/vendor/**"]'
    recommendation_format: "markdown"
    fail_on_unfixed: "false"
    commit_message_prefix: "[aiops-sca]"
    git_user_name: "aiops-sca[bot]"
    git_user_email: "aiops-sca-bot@example.com"
    lint_retry_on_failure: "true"
    allow_severities: '["medium","high","critical","error"]'
    exclude_rules: '["AWS001","terraform_required_providers"]'
    max_token_context_bytes: "0"
    audit_log: "true"
    re_lint_after_apply: "true"
    re_lint_cmd: 'tflint --recursive --format json > output/re_lint.json || true'
    re_lint_output_glob: "output/re_lint.json"
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    AZURE_OPENAI_ENDPOINT: ${{ secrets.AZURE_OPENAI_ENDPOINT }}
    AZURE_OPENAI_API_KEY: ${{ secrets.AZURE_OPENAI_API_KEY }}
    AZURE_OPENAI_API_VERSION: "2024-06-01"
```
