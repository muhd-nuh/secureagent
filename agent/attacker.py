import os
import requests
from google import genai
from google.genai import types
from agent.sandbox import deploy_sandbox
from agent.logger import get_logger

logger = get_logger("attacker")

# Response signals that confirm a successful attack in the sandbox response body.
# Both body content and HTTP status are checked — see run_attack for full logic.
ATTACK_SUCCESS_SIGNALS = {
    "SQL Injection": [
        "welcome admin", "sqlerror", "syntax error",
        "sqlite3.", "uid", "admin", "password"
    ],
    "Cross-Site Scripting (XSS)": [
        "<script>", "alert(", "onerror=", "<img"
    ]
}

# Signals that indicate the attack was blocked — used as fallback detection.
ATTACK_FAILURE_SIGNALS = ["invalid credentials", "failed", "unauthorized", "error"]

MAX_RETRIES = 3


def run_attack(sandbox_url: str, finding) -> dict:
    """
    Fires the attack payload against the sandbox /test endpoint.
    Injects the payload into the exact field Gemini identified as vulnerable.
    Uses two-layer detection: known success signals + HTTP status fallback.
    Returns a proof dict with status code, response body, and success flag.
    """
    target_url = f"{sandbox_url}/test"

    post_data = {
        finding.attack_field: finding.attack_payload,
        "password": "anything"
    }

    try:
        response = requests.post(target_url, data=post_data, timeout=10)

        # Primary check: known success signals in response body
        signals = ATTACK_SUCCESS_SIGNALS.get(finding.vulnerability, [])
        body_match = any(signal in response.text.lower() for signal in signals)

        # Fallback: HTTP 200 with no failure signals also counts as attack succeeded
        # Handles sandboxes where response wording doesn't match known signals
        body_failure = any(signal in response.text.lower() for signal in ATTACK_FAILURE_SIGNALS)
        attack_succeeded = body_match or (response.status_code == 200 and not body_failure)

        logger.info(f"Attack result, succeeded: {attack_succeeded}, status: {response.status_code}")

        return {
            "status_code": response.status_code,
            "response_body": response.text[:500],
            "attack_succeeded": attack_succeeded,
            "payload_used": finding.attack_payload,
            "field_targeted": finding.attack_field
        }

    except Exception as e:
        logger.error(f"Attack request failed: {e}")
        return {
            "status_code": None,
            "response_body": str(e),
            "attack_succeeded": False,
            "payload_used": finding.attack_payload,
            "field_targeted": finding.attack_field
        }


def deploy_fix_and_verify(finding, gcp_project_id: str, mr_iid: str) -> dict:
    """
    Deploys Gemini's fixed code to the sandbox and re-runs the same attack.
    Uses fixed_sandbox_template for dynamic fix verification if available.
    Returns after proof dict, same structure as run_attack output.
    """
    class FixedFinding:
        vulnerable_code = finding.fixed_code
        attack_payload = finding.attack_payload
        attack_field = finding.attack_field
        vulnerability = finding.vulnerability
        sandbox_template = getattr(finding, 'fixed_sandbox_template', None)

    logger.info("Deploying fixed code to sandbox...")
    fixed_sandbox_url = deploy_sandbox(FixedFinding(), gcp_project_id, mr_iid)

    logger.info("Running attack against fixed sandbox...")
    after_proof = run_attack(fixed_sandbox_url, finding)

    if not after_proof["attack_succeeded"]:
        logger.info("Fix verified, attack blocked successfully")
    else:
        logger.warning("Fix did not block attack, retry needed")

    return after_proof


def get_improved_fix(finding, failed_proof: dict):
    """
    Asks Gemini to generate an improved fix using the failed attempt as context.
    Passes the exact payload and server response so Gemini understands what bypassed the fix.
    Returns a finding-like object with the improved fix, or None on failure.
    """
    retry_prompt = (
        f"Your previous fix attempt for a {finding.vulnerability} vulnerability failed.\n\n"
        f"Previous fix code:\n{finding.fixed_code}\n\n"
        f"Attack payload that bypassed the fix:\n{failed_proof['payload_used']}\n\n"
        f"Server response showing the fix was bypassed:\n{failed_proof['response_body']}\n\n"
        "Analyze why your previous fix was bypassed by this specific attack and generate "
        "an improved, completely secure replacement for the vulnerable line only. "
        "Return ONLY the secure replacement line, no function definitions, "
        "no inline comments, no markdown formatting."
    )

    try:
        client = genai.Client(
            vertexai=True,
            project=os.getenv("GOOGLE_CLOUD_PROJECT"),
            location=os.getenv("GOOGLE_CLOUD_LOCATION")
        )

        response = client.models.generate_content(
            model='gemini-3.5-flash',
            contents=retry_prompt,
            config=types.GenerateContentConfig(temperature=0.1),
        )

        improved_code = response.text.strip()
        logger.info(f"Improved fix from Gemini: {improved_code}")

        class ImprovedFinding:
            vulnerable_code = improved_code
            fixed_code = improved_code
            attack_payload = finding.attack_payload
            attack_field = finding.attack_field
            vulnerability = finding.vulnerability

        return ImprovedFinding()

    except Exception as e:
        logger.error(f"Failed to get improved fix from Gemini: {e}")
        return None


def iterative_fix_loop(finding, before_proof: dict, gcp_project_id: str, mr_iid: str) -> tuple:
    """
    Attempts to verify the fix up to MAX_RETRIES times.
    On each failed attempt, sends the failure context back to Gemini for an improved fix.
    Stops early as soon as the fix is verified successfully.
    Returns (final_after_proof, attempts_used, requires_manual_review).
    """
    current_finding = finding
    after_proof = None

    for attempt in range(1, MAX_RETRIES + 1):
        logger.info(f"Fix attempt {attempt} of {MAX_RETRIES}...")

        after_proof = deploy_fix_and_verify(current_finding, gcp_project_id, mr_iid)

        if not after_proof["attack_succeeded"]:
            logger.info(f"Fix verified on attempt {attempt}")
            return after_proof, attempt, False

        logger.warning(f"Attempt {attempt} failed, requesting improved fix from Gemini...")
        improved_finding = get_improved_fix(current_finding, after_proof)

        if improved_finding is None:
            break

        current_finding = improved_finding

    logger.warning(f"All {MAX_RETRIES} attempts exhausted, flagging for manual review")
    return after_proof, MAX_RETRIES, True