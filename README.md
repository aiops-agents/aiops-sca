# Open Source Project
## **Static Code Analysis (SCA) AI Agent for Infrastructure-as-Code**

**Status:** Underconstruction. For any queries please reachout to @TheSolutionArchitect.

**Plan A:** AIOps Static Code Analysis Agent; **Objective:** "Agentic AI to analyze Terraform lint outputs and optionally auto-fix and push changes"


**Usages**
```
- name: AIOps SCA Agent
        uses: aiops-agents/aiops-sca@v1
        with:
          enable: true
          scope: '["infra/**/*.tf"]'
          input_dir: "./input"
          output_dir: "./output"
          llm_provider: "azure_openai"
          llm_model: "gpt-4o-mini"   # Azure deployment name
          show_recommendation: true
          auto_apply: true
          lint_format: "auto"
          apply_mode: "commit"       # or "pr" or "dry-run"
          max_lines_changed: "200"
          max_files_changed: "10"
          protected_paths: '["infra/modules/vendor/**"]'
          recommendation_format: "markdown"
          fail_on_unfixed: "false"
          commit_message_prefix: "[aiops-sca]"
          git_user_name: "aiops-sca[bot]"
          git_user_email: "aiops-sca-bot@example.com"
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          AZURE_OPENAI_ENDPOINT: ${{ secrets.AZURE_OPENAI_ENDPOINT }}
          AZURE_OPENAI_API_KEY: ${{ secrets.AZURE_OPENAI_API_KEY }}
          AZURE_OPENAI_API_VERSION: "2024-06-01"
```
