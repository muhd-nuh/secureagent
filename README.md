# SecureAgent

An AI-powered application security agent that automatically detects, proves, and fixes vulnerabilities in your GitLab repository.

## What it does

1. Triggers automatically on GitLab Merge Request events via webhook
2. Analyses changed Python and JavaScript files for SQL Injection and XSS vulnerabilities using Gemini 3.5 Flash
3. Deploys an ephemeral Cloud Run sandbox and executes a real HTTP attack against the vulnerable code
4. Captures before/after proof - HTTP responses showing attack success and fix verification
5. Generates a fix, proves it blocks the attack, and opens a GitLab Merge Request automatically
6. Posts a full security report on the developer's MR

## Tech Stack
- Gemini 3.5 Flash via Vertex AI
- Google Cloud ADK
- Google Cloud Run
- GitLab API + Webhook
- Python / Flask
  
## Setup
See `.env.example` for required environment variables.

## Hackathon
Submitted for the Google Cloud Rapid Agent Hackathon — GitLab track.

## License
MIT
