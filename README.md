# SecureAgent

An AI-powered application security agent that automatically detects, proves, and fixes vulnerabilities in your GitLab repository.

## What it does
1. Triggers on GitLab Merge Request events via webhook
2. Analyses changed Python and JavaScript files for SQL Injection and XSS vulnerabilities using Gemini 3.5 Flash
3. Deploys an ephemeral sandbox to Cloud Run and executes a real attack against the vulnerable code
4. Generates a fix, proves it blocks the attack, and opens a GitLab Merge Request automatically

## Tech Stack
- Gemini 3.5 Flash via Vertex AI
- Google Cloud Agent Builder (ADK)
- Google Cloud Run
- GitLab MCP
- Python / Flask

## Status
Work in progress

## Setup
See `.env.example` for required environment variables.

## License
MIT
