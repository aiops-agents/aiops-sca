# Open Source Project
## **Static Code Analysis (SCA) AI Agent for Infrastructure-as-Code**

**Status:** Testing in-progress. If you have any queries, please reach out to @TheSolutionArchitect.

**Release v1.0.0:** AIOps Static Code Analysis Agent; **Objective:** "Agentic AI to analyze Terraform lint outputs and optionally auto-fix and push changes"

**Usage:** Please [refer here](https://github.com/aiops-agents/aiops-gh-workflows) for the GitHub workflow usage. 

**Connect to OpenAI:** Microsoft Foundry model deployment
```
endpoint = "https://aiops-az-openai.cognitiveservices.azure.com/"
model_name = "gpt-4o-mini"
deployment = "gpt-4o-mini"

subscription_key = "<your-api-key>"
api_version = "2024-12-01-preview"
```
**Short Version:**

```
      - name: AIOps SCA Agent
        uses: aiops-agents/aiops-sca@dev
        with:
          llm_provider: azure_openai
          llm_model: gpt-4o-mini
          scope: '["infra/**/*.tf"]'
          tf_root_dir: infra
          re_lint_after_apply: true
          re_lint_tooling: built-in
          re_lint_tools: '["tflint","tfsec","checkov"]'
        env:
          GITHUB_TOKEN: ${{ github.token }}
          AZURE_OPENAI_ENDPOINT: ${{ secrets.AZURE_OPENAI_ENDPOINT }}
          AZURE_OPENAI_API_KEY: ${{ secrets.AZURE_OPENAI_API_KEY }}
          AZURE_OPENAI_API_VERSION: ${{ secrets.AZURE_OPENAI_API_VERSION }}

```

**Extended Version:** with all supported parameters. Please check actions.yml
```
- name: AIOps SCA Agent
  uses: ai-agents/aiops-sca@v1
  with:
    llm_provider: azure_openai
    llm_model: gpt-4o-mini
    scope: ["infra/**/*.tf"]
    tf_root_dir: infra
    re_lint_after_apply: true
    re_lint_tooling: built-in
    re_lint_tools: ["tflint","tfsec","checkov"]
    enable: true
    input_dir: ./input
    output_dir: ./output
    show_recommendation: true
    auto_apply: false
    lint_format: auto
    apply_mode: commit
    max_lines_changed: 200
    max_files_changed: 10
    protected_paths: []
    recommendation_format: markdown
    fail_on_unfixed: false
    commit_message_prefix: [aiops-sca]
    git_user_name: aiops-sca[bot]
    git_user_email: aiops-sca-bot@example.com
    temperature: 0.2
    max_tokens: 4000
    lint_retry_on_failure: true
    allow_severities: ["low","medium","high","critical","warning","error"]
    exclude_rules: []
    max_token_context_bytes: 0
    audit_log: true
    sarif_output_enabled: true
    sarif_pre_path: output/aiops-sca.sarif
    sarif_post_path: output/aiops-sca-post.sarif
    tool_sarif_enabled: true
    tool_sarif_mode: convert
    tool_sarif_dir: output/sarif
    tool_sarif_post_mode: native
    tool_sarif_post_dir: output/sarif-post
    patches_enabled: true
    patches_dir: output/patches
    combined_patch_name: changes.patch
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    AZURE_OPENAI_ENDPOINT: ${{ secrets.AZURE_OPENAI_ENDPOINT }}
    AZURE_OPENAI_API_KEY: ${{ secrets.AZURE_OPENAI_API_KEY }}
    AZURE_OPENAI_API_VERSION: "2024-06-01"
```
