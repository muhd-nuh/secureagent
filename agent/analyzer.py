import os
import json
from google import genai
from google.genai import types
from pydantic import BaseModel, Field
from typing import List
from dotenv import load_dotenv

load_dotenv()

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
    attack_field: str = Field(description="The input field name to inject the payload into e.g. username, email")
    real_world_impact: str = Field(description="Explanation of the impact on users/the system")
    fixed_code: str = Field(description="Secure version of the code without inline comments")
    why_fix_works: str = Field(description="Technical reason why this remediation resolves the flaw")
    developer_lesson: str = Field(description="One sentence takeaway for the developer")

class SecurityReport(BaseModel):
    findings: List[Finding]


# Secure patterns we expect to see in a properly fixed vulnerability.
# If Gemini's fix doesn't contain any of these, it likely isn't actually fixing the problem.
SECURE_PATTERNS = {
    "SQL Injection": ["parameterized", "prepared", "?", "%s", "execute(", "cursor"],
    "Cross-Site Scripting (XSS)": ["escape", "sanitize", "bleach", "markupsafe", "html.escape", "textContent", "innerText", "DOMPurify", "encodeURIComponent"]
}

# Patterns that should never appear in generated fix code.
# These indicate dangerous operations that could introduce new vulnerabilities.
DANGEROUS_PATTERNS = [
    "eval(", "exec(", "os.system(",
    "shell=True", "innerHTML", "document.write(",
    "os.popen", "pickle.loads", "shutil.copyfile"
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
        "- vulnerable_code: Copy ONLY the single vulnerable line from the code — do not include function definition or surrounding code. "
        "For SQL Injection, rewrite the line using string concatenation format if needed: "
        "query = \"SELECT * FROM users WHERE username = '\" + username + \"'\"\n"
        "- why_vulnerable: Explain clearly why this code is vulnerable in plain English, "
        "write as if explaining to a junior developer\n"
        "- attack_payload: Provide a real working exploit payload that would trigger this vulnerability\n"
        "- attack_field: The exact HTML form field name or URL parameter to inject the payload into\n"
        "- real_world_impact: Describe the worst case scenario if a real attacker exploited this, "
        "be specific about what data or access they could gain\n"
        "- fixed_code: Provide ONLY the secure replacement for the vulnerable line — "
        "do not include function definitions or surrounding code, "
        "no inline comments inside the code block, no markdown formatting\n"
        "- why_fix_works: Explain technically why the fix prevents the attack\n"
        "- developer_lesson: One sentence the developer should remember to avoid this class of vulnerability in future\n"
        "- If no vulnerabilities found, return an empty findings array\n"
    )

    return prompt


def call_gemini(prompt: str) -> SecurityReport:
    """
    Sends the analysis prompt to Gemini 3.5 Flash via Vertex AI.
    Returns a SecurityReport containing all findings.
    Temperature set low (0.1) to keep responses analytical and consistent.
    """
    client = genai.Client(
        vertexai=True,
        project=os.getenv("GOOGLE_CLOUD_PROJECT"),
        location=os.getenv("GOOGLE_CLOUD_LOCATION")
    )

    response = client.models.generate_content(
        model='gemini-3.5-flash',
        contents=prompt,
        config=types.GenerateContentConfig(
            response_mime_type="application/json",
            response_schema=SecurityReport,
            temperature=0.1
        ),
    )

    data = json.loads(response.text)
    return SecurityReport(**data)


def validate_fix(finding: Finding) -> tuple:
    """
    Validates Gemini's generated fix before it gets deployed or pushed as an MR.
    Two checks:
    1. No dangerous patterns (eval, exec, os.system etc.)
    2. Contains expected secure patterns for the vulnerability type
    Returns (is_valid: bool, reason: str)
    """
    vuln_type = finding.vulnerability

    # Strip comment lines before checking to avoid false positives
    # e.g. a comment saying "# no parameterized query" would otherwise pass the check
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