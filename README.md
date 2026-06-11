# SecureAgent
An AI-powered application security agent that automatically detects, proves, and fixes vulnerabilities in GitLab Merge Requests.

> "Don't just find vulnerabilities — understand them, prove them, fix them."

## What It Does
1. Triggers automatically on GitLab MR events via webhook
2. Analyses changed Python and JavaScript files for SQL Injection and XSS using Gemini 3.5 Flash via Vertex AI
3. Deploys an ephemeral Cloud Run sandbox with the vulnerable code
4. Fires a real HTTP attack against the sandbox — proves the vulnerability is exploitable
5. Generates a parameterized fix, deploys it, and verifies the attack is blocked
6. Creates a GitLab Issue with full vulnerability report and before/after HTTP proof
7. Opens a fix MR on `secureagent/fixes` branch with the secure code
8. Posts a validation summary and attack proof table on the developer's original MR

## Tech Stack
- **Gemini 3.5 Flash** via Vertex AI — vulnerability analysis and fix generation
- **Google Cloud ADK** — agent orchestration with GitLab MCP toolset
- **GitLab MCP Server** — issue and MR creation via official MCP protocol
- **Google Cloud Run** — ephemeral sandbox deployment per MR
- **Google Cloud Build** — container image builds
- **Google Cloud Secret Manager** — secure credential management
- **Python / Flask** — webhook listener and pipeline orchestration

## AI Security Controls
1. Prompt injection detection - Scans developer code before sending to Gemini (LLM01)
2. Fix validation - Verifies secure patterns in generated fixes (LLM05)
3. Sandbox template validation - Checks for dangerous imports/patterns (LLM05)
4. Rate limiting - 50 scans/min per project (LLM10)
5. Human approval gate - Fix MR requires developer review before merge (LLM06)

## Hosted URL
https://secureagent-265054878962.us-central1.run.app

## Known Limitations
- XSS live sandbox proof deferred to Phase 2
- Cross-file and second-order vulnerability detection planned for Phase 3
- Cloud Run full pipeline requires Cloud Build and Run API permissions

## Setup
See `.env.example` for required environment variables.

## Hackathon
Submitted for the Google Cloud Rapid Agent Hackathon — GitLab track.

## License
MIT
