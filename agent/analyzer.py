import os
import json
import re
from google import genai
from google.genai import types
from pydantic import BaseModel, Field
from typing import List
from dotenv import load_dotenv

load_dotenv()

logger = get_logger("analyzer")

from agent.logger import get_logger
from agent.secrets import get_secret

# Structured data models for Gemini's security analysis output.
# Pydantic enforces the schema at the engine level, no manual JSON parsing needed.

class Finding(BaseModel):
    vulnerability: str = Field(description="Either 'SQL Injection' or 'Cross-Site Scripting (XSS)'")
    owasp_category: str = Field(description="Must strictly be 'A05:2025 - Injection'")
    severity: str = Field(description="CRITICAL, HIGH, MEDIUM, or LOW based on CVSS metrics")
    line_number: int = Field(description="The starting line number where the vulnerability is located")
    vulnerable_code: str = Field(description="The exact snippet of vulnerable code")
    why_vulnerable: str = Field(description="Detailed explanation of the flaw")
    attack_payload: str = Field(description="The exploit payload used to demonstrate the vulnerability")
    attack_field: str = Field(description="The exact parameter name used in the vulnerable function, not a generic name")
    real_world_impact: str = Field(description="Explanation of the impact on users/the system")
    fixed_code: str = Field(description="Secure version of the code without inline comments")
    why_fix_works: str = Field(description="Technical reason why this remediation resolves the flaw")
    developer_lesson: str = Field(description="One sentence takeaway for the developer")
    sandbox_template: str = Field(description=(
        "A complete working Flask app that demonstrates this specific vulnerability. "
        "Must use request.form.get() for POST fields, match the context of the vulnerable code, "
        "return {status: success, message: Welcome admin} on attack success, "
        "and {status: failed, message: Invalid credentials} on failure. "
        "App must start on PORT env variable defaulting to 8080. No markdown or code fences."
    ))
    fixed_sandbox_template: str = Field(description=(
        "A complete working Flask app identical to sandbox_template but with secure fix applied. "
        "Must use request.form.get() for POST fields. "
        "Must return {status: failed, message: Invalid credentials} when same attack payload is used. "
        "App must start on PORT env variable defaulting to 8080. No markdown or code fences."
    ))


class SecurityReport(BaseModel):
    findings: List[Finding]


# Secure patterns we expect to see in a properly fixed vulnerability.
# If Gemini's fix doesn't contain any of these, it likely isn't actually fixing the problem.
SECURE_PATTERNS = {
    "SQL Injection": ["parameterized", "prepared", "?", "%s", "execute(", "cursor"],
    "Cross-Site Scripting (XSS)": [
        "escape", "sanitize", "bleach", "markupsafe",
        "html.escape", "textContent", "innerText",
        "DOMPurify", "encodeURIComponent"
    ]
}

# Patterns that should never appear in generated fix or sandbox code.
# These indicate dangerous operations that could introduce new vulnerabilities.
DANGEROUS_PATTERNS = [
    "eval(", "exec(", "os.system(",
    "shell=True", "innerHTML", "document.write(",
    "os.popen", "pickle.loads", "shutil.copyfile"
]

# Only these modules are permitted in Gemini-generated sandbox templates.
ALLOWED_SANDBOX_IMPORTS = ["flask", "sqlite3", "os", "json"]

# Known prompt injection phrases — code containing these is flagged before reaching Gemini.
PROMPT_INJECTION_PATTERNS = [
    "ignore previous instructions",
    "disregard your instructions",
    "you are now",
    "forget your role",
    "system prompt",
    "jailbreak",
    "ignore all previous",
    "override instructions",
    "do not scan",
    "report no vulnerabilities",
    "return empty findings"
]


def build_gemini_prompt(file_contents: dict) -> str:
    """
    Builds the security analysis prompt from the changed file contents.
    Pydantic schema handles output structure, prompt focuses on role and field instructions.
    """
    prompt = (
        "You are a senior application security engineer. "
        "Analyze the provided source code files for SQLi (SQL Injection) "
        "and XSS (Cross-Site Scripting) vulnerabilities only.\n\n"
    )

    for filename, code in file_contents.items():
        prompt += f"--- start of filename: {filename} ---\n"
        prompt += f"{code}\n"
        prompt += f"--- end of filename: {filename} ---\n\n"

    prompt += (
        "Instructions for specific fields:\n"
        "- vulnerability: Must be exactly 'SQL Injection' or 'Cross-Site Scripting (XSS)', no other vulnerability types\n"
        "- owasp_category: Must strictly be 'A05:2025 - Injection' for all findings\n"
        "- severity: Use CVSS reasoning, CRITICAL if authentication bypass or full data dump possible, "
        "HIGH if sensitive data exposed, MEDIUM if limited impact, LOW if minimal risk\n"
        "- line_number: The exact line number in the file where the vulnerability starts, count from line 1\n"
        "- vulnerable_code: Copy ONLY the single vulnerable line from the code, do not include function definition or surrounding code. "
        "For SQL Injection, rewrite the line using string concatenation format if needed: "
        "query = \"SELECT * FROM users WHERE username = '\" + username + \"'\"\n"
        "- why_vulnerable: Explain clearly why this code is vulnerable in plain English, "
        "write as if explaining to a junior developer\n"
        "- attack_payload: Provide a real working exploit payload that would trigger this vulnerability\n"
        "- attack_field: Must be the exact parameter name used in the vulnerable function, "
        "not a generic name. For example if the function uses 'search_term', attack_field must be 'search_term'\n"
        "- real_world_impact: Describe the worst case scenario if a real attacker exploited this, "
        "be specific about what data or access they could gain\n"
        "- fixed_code: Provide ONLY the secure replacement for the vulnerable line, "
        "do not include function definitions or surrounding code, "
        "no inline comments inside the code block, no markdown formatting\n"
        "- why_fix_works: Explain technically why the fix prevents the attack\n"
        "- developer_lesson: One sentence the developer should remember to avoid this class of vulnerability in future\n"
        "- If no vulnerabilities found, return an empty findings array\n"
        "- IMPORTANT: You MUST flag ALL instances of string concatenation in SQL queries as SQL Injection, "
        "regardless of how simple or short the function is\n"
        "- Do not skip findings because the function lacks surrounding context or seems incomplete\n"
        "- Every file must be scanned independently — do not skip any file\n"
    )

    prompt += (
        "SANDBOX TEMPLATE REQUIREMENTS:\n"
        "- sandbox_template: Generate a complete working Flask app that accurately demonstrates this specific vulnerability\n"
        "- Create a database table that matches the context of the vulnerable code "
        "(users table for auth, products table for search, etc.)\n"
        "- Use ONLY sqlite3.connect(':memory:') for the database — do NOT use file paths or URI formats\n"
        "- Initialize the database inside the /test endpoint, not in a separate init_db() function\n"
        "- Each request must create its own in-memory database with test data inserted fresh\n"
        "- Cloud Run containers have a read-only filesystem — file-based databases will cause deployment failure\n"
        "- The /test endpoint must use request.form.get() to read POST fields\n"
        "- Use the same field name as attack_field in the /test endpoint\n"
        "- The app must return exactly {\"status\": \"success\", \"message\": \"Welcome admin\"} when attack succeeds\n"
        "- The app must return HTTP 401 with {\"status\": \"failed\", \"message\": \"Invalid credentials\"} when attack fails\n"
        "- Use return jsonify({\"status\": \"failed\", \"message\": \"Invalid credentials\"}), 401 for failed attempts\n"
        "- App must start on PORT environment variable defaulting to 8080\n"
        "- Do not include any markdown formatting or code fences in the template\n"
        "- The template must be valid Python that runs without modification\n"
        "FIXED SANDBOX TEMPLATE REQUIREMENTS:\n"
        "- fixed_sandbox_template: Generate the same Flask app as sandbox_template but with the vulnerable code replaced by the secure fix\n"
        "- Must use request.form.get() to read POST fields, not request.get_json()\n"
        "- The fixed code must be properly integrated into the login function\n"
        "- When the same attack payload is fired, must return exactly {\"status\": \"failed\", \"message\": \"Invalid credentials\"}\n"
        "- Do not include any markdown formatting or code fences in the template\n"
        "- The template must be valid Python that runs without modification\n"
    )

    return prompt


def call_gemini(prompt: str) -> SecurityReport:
    """
    Sends the analysis prompt to Gemini 3.5 Flash via Vertex AI.
    Returns a SecurityReport containing all findings.
    Temperature set low (0.1) to keep responses analytical and consistent.
    Max output tokens set high to accommodate full sandbox template generation.
    """
    client = genai.Client(
        vertexai=True,
        project=os.getenv("GOOGLE_CLOUD_PROJECT"),
        location=get_secret("GOOGLE_CLOUD_LOCATION"),
    )

    response = client.models.generate_content(
        model='gemini-3.5-flash',
        contents=prompt,
        config=types.GenerateContentConfig(
            response_mime_type="application/json",
            response_schema=SecurityReport,
            temperature=0.1,
            max_output_tokens=16384
        ),
    )

    data = json.loads(response.text)
    return SecurityReport(**data)


def validate_fix(finding: Finding) -> tuple:
    """
    Validates Gemini's generated fix before deployment or MR creation.
    Strips comments first to avoid false positives, then checks for:
    1. Dangerous patterns (eval, exec, os.system etc.)
    2. Expected secure patterns for the vulnerability type
    Returns (is_valid, reason).
    """
    vuln_type = finding.vulnerability

    # Strip comment lines before checking to avoid false positives
    # e.g. a comment saying "# no parameterized query" would otherwise pass the secure pattern check
    code_lines = [
        line for line in finding.fixed_code.split("\n")
        if not line.strip().startswith("#")
    ]
    clean_code = "\n".join(code_lines)

    for pattern in DANGEROUS_PATTERNS:
        if pattern in clean_code:
            return False, f"Dangerous pattern detected: {pattern}"

    expected_patterns = SECURE_PATTERNS.get(vuln_type, [])
    if not any(p in clean_code for p in expected_patterns):
        return False, f"No secure patterns found for {vuln_type}"

    return True, "Fix validated"


def validate_sandbox_template(template: str) -> tuple:
    """
    Validates Gemini's generated sandbox template before Cloud Run deployment.
    Checks for dangerous patterns and unexpected imports beyond the allowed safe set.
    Returns (is_valid, reason).
    """
    for pattern in DANGEROUS_PATTERNS:
        if pattern in template:
            return False, f"Dangerous pattern detected in sandbox template: {pattern}"

    # Only allow known safe imports in sandbox code
    imports_found = re.findall(r'^(?:import|from)\s+(\w+)', template, re.MULTILINE)
    for module in imports_found:
        if module not in ALLOWED_SANDBOX_IMPORTS:
            return False, f"Unexpected import in sandbox template: {module}"

    return True, "Sandbox template validated"


def detect_prompt_injection(file_contents: dict) -> tuple:
    """
    Scans developer code for prompt injection attempts before sending to Gemini.
    Protects against malicious code crafted to override SecureAgent's analysis instructions.
    Returns (injection_detected, filename, pattern_found).
    """
    for filename, code in file_contents.items():
        for pattern in PROMPT_INJECTION_PATTERNS:
            if pattern.lower() in code.lower():
                logger.warning(f"Prompt injection attempt detected in {filename}, pattern: {pattern}")
                return True, filename, pattern
    return False, None, None