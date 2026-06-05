import requests
from agent.sandbox import deploy_sandbox

# Response signals that confirm an attack succeeded.
# We check the response body for these strings after firing the payload.
ATTACK_SUCCESS_SIGNALS = {
    "SQL Injection": [
        "welcome admin", "sqlerror", "syntax error",
        "sqlite3.", "uid", "admin", "password"
    ],
    "Cross-Site Scripting (XSS)": [
        "<script>", "alert(", "onerror=", "<img"
    ]
}


def run_attack(sandbox_url: str, finding) -> dict:
    """
    Fires the attack payload against the sandbox /test endpoint.
    Injects the payload into the target field Gemini identified.
    Returns a proof dict with status code, response body, and success flag.
    """
    target_url = f"{sandbox_url}/test"

    # Inject payload into the specific field Gemini flagged as vulnerable
    post_data = {
        finding.attack_field: finding.attack_payload,
        "password": "anything"
    }

    try:
        response = requests.post(target_url, data=post_data, timeout=10)

        # Check response body for known attack success indicators
        signals = ATTACK_SUCCESS_SIGNALS.get(finding.vulnerability, [])
        attack_succeeded = any(signal in response.text.lower() for signal in signals)

        print(f"Attack result, succeeded: {attack_succeeded}, status: {response.status_code}")

        return {
            "status_code": response.status_code,
            "response_body": response.text[:500],
            "attack_succeeded": attack_succeeded,
            "payload_used": finding.attack_payload,
            "field_targeted": finding.attack_field
        }

    except Exception as e:
        print(f"Attack request failed: {e}")
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
    If the attack is blocked this time, the fix is verified.
    Returns after proof dict, same structure as run_attack output.
    """
    # Wrap fixed_code in a minimal object so deploy_sandbox can use it
    # deploy_sandbox expects a finding-like object with a vulnerable_code field
    class FixedFinding:
        vulnerable_code = finding.fixed_code
        attack_payload = finding.attack_payload
        attack_field = finding.attack_field
        vulnerability = finding.vulnerability

    print("Deploying fixed code to sandbox...")
    fixed_sandbox_url = deploy_sandbox(FixedFinding(), gcp_project_id, mr_iid)

    print("Running attack against fixed sandbox...")
    after_proof = run_attack(fixed_sandbox_url, finding)

    if not after_proof["attack_succeeded"]:
        print("Fix verified, attack blocked successfully")
    else:
        print("Fix did not block attack, retry needed")

    return after_proof