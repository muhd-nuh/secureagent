import os
import time
import threading
from collections import defaultdict
from flask import Flask, request, jsonify
from dotenv import load_dotenv
import requests as http_requests
from agent.analyzer import build_gemini_prompt, call_gemini, validate_fix, validate_sandbox_template, detect_prompt_injection
from agent.sandbox import deploy_sandbox
from agent.attacker import run_attack, iterative_fix_loop
from agent.gitlab_integration import create_gitlab_issue, create_merge_request, post_final_report
from agent.logger import get_logger
from agent.secrets import get_secret

load_dotenv()

app = Flask(__name__)
logger = get_logger("main")

GITLAB_WEBHOOK_SECRET = get_secret("GITLAB_WEBHOOK_SECRET")
GITLAB_TOKEN = get_secret("GITLAB_TOKEN")

# Placeholder proof used when sandbox verification is not available for a vuln type (e.g. XSS)
NO_PROOF = {
    "status_code": "N/A",
    "response_body": "Sandbox proof not available",
    "attack_succeeded": False,
    "payload_used": "",
    "field_targeted": ""
}

# In-memory rate limiting, max 50 scans per 60 seconds per GitLab project
# Resets on Flask restart — Redis recommended for production scale
call_tracker = defaultdict(list)
RATE_LIMIT = 50
RATE_WINDOW = 60


def check_rate_limit(gitlab_project_id) -> bool:
    """
    Prevents abuse by limiting scans per project per time window.
    Returns False if the project has exceeded the limit.
    """
    now = time.time()
    call_tracker[gitlab_project_id] = [
        t for t in call_tracker[gitlab_project_id]
        if now - t < RATE_WINDOW
    ]
    if len(call_tracker[gitlab_project_id]) >= RATE_LIMIT:
        return False
    call_tracker[gitlab_project_id].append(now)
    return True


def verify_gitlab_token(request):
    """
    Verifies the X-Gitlab-Token header on incoming webhook requests.
    Blocks unauthorized traffic before any processing occurs.
    """
    token = request.headers.get("X-Gitlab-Token")
    if not token or token != GITLAB_WEBHOOK_SECRET:
        return False
    return True


def get_mr_changed_files(gitlab_project_id, mr_iid):
    """
    Fetches the list of files changed in an MR via GitLab API.
    More reliable than reading from the webhook payload which can be incomplete.
    """
    url = f"https://gitlab.com/api/v4/projects/{gitlab_project_id}/merge_requests/{mr_iid}/changes"
    headers = {"PRIVATE-TOKEN": GITLAB_TOKEN}
    response = http_requests.get(url, headers=headers)
    data = response.json()
    return [change["new_path"] for change in data.get("changes", [])]


def fetch_file_contents(gitlab_project_id, file_paths, branch):
    """
    Fetches file contents directly from GitLab API for the given branch.
    Returns {filename: contents} dictionary.
    Skips files that cannot be fetched without crashing the pipeline.
    """
    file_contents = {}

    for filepath in file_paths:
        try:
            encoded_path = filepath.replace("/", "%2F")
            url = f"https://gitlab.com/api/v4/projects/{gitlab_project_id}/repository/files/{encoded_path}/raw?ref={branch}"
            headers = {"PRIVATE-TOKEN": GITLAB_TOKEN}
            response = http_requests.get(url, headers=headers)

            if response.status_code == 200:
                filename = os.path.basename(filepath)
                file_contents[filename] = response.text
                logger.info(f"Fetched: {filename}")
            else:
                logger.warning(f"Could not fetch {filepath}, status {response.status_code}, skipping")

        except Exception as e:
            logger.warning(f"Error fetching {filepath}, {e}, skipping")

    return file_contents


def post_mr_comment(gitlab_project_id, mr_iid, message):
    """
    Posts a comment on a GitLab MR via API.
    Used to keep the developer informed of pipeline progress and findings.
    """
    url = f"https://gitlab.com/api/v4/projects/{gitlab_project_id}/merge_requests/{mr_iid}/notes"
    headers = {"PRIVATE-TOKEN": GITLAB_TOKEN}
    response = http_requests.post(url, headers=headers, json={"body": message})
    if response.status_code == 201:
        logger.info(f"Comment posted to MR #{mr_iid}")
    else:
        logger.error(f"Failed to post comment: {response.status_code}")


@app.route("/webhook", methods=["POST"])
def webhook():
    """
    Receives GitLab MR webhook events.
    Returns 200 immediately and processes the pipeline in a background thread
    to avoid GitLab webhook timeouts.
    """
    if not verify_gitlab_token(request):
        return jsonify({"error": "Unauthorized"}), 401

    payload = request.get_json()

    if payload.get("object_kind") != "merge_request":
        return jsonify({"message": "Ignored, not an MR event"}), 200

    thread = threading.Thread(target=process_pipeline, args=(payload,))
    thread.start()

    return jsonify({"message": "Pipeline triggered"}), 200


def process_pipeline(payload):
    """
    Main SecureAgent pipeline, runs in a background thread.
    Flow: rate check, fetch files, prompt injection check, Gemini analysis,
    sandbox deployment, attack execution, fix verification, GitLab reporting.
    """
    mr_iid = payload["object_attributes"]["iid"]
    branch = payload["object_attributes"]["source_branch"]
    gitlab_project_id = payload["project"]["id"]
    gcp_project_id = os.getenv("GOOGLE_CLOUD_PROJECT")
    username = payload["user"]["username"]

    # Rate limit check — prevents abuse and runaway costs
    if not check_rate_limit(gitlab_project_id):
        logger.warning(f"Rate limit exceeded for project {gitlab_project_id}, skipping scan")
        post_mr_comment(gitlab_project_id, mr_iid, ":red_circle: **SecureAgent:** Rate limit exceeded. Please wait before pushing again.")
        return

    # Only process MRs that are opened or updated with new commits
    action = payload["object_attributes"].get("action")
    if action not in ["open", "update"]:
        logger.info(f"Ignored, MR action: {action}")
        return

    # Step 1: Get changed files
    changed_files = get_mr_changed_files(gitlab_project_id, mr_iid)
    logger.info(f"Changed files: {changed_files}")

    # Step 2: Filter for supported languages, exclude SecureAgent's own fix files
    supported_files = [
        f for f in changed_files
        if (f.endswith(".py") or f.endswith(".js"))
        and not f.startswith("fixes/")
    ]

    if not supported_files:
        logger.info("No supported files, pipeline stopped")
        return

    # Step 3: Fetch file contents from GitLab
    file_contents = fetch_file_contents(gitlab_project_id, supported_files, branch)

    if not file_contents:
        logger.info("No file contents retrieved, pipeline stopped")
        return

    logger.info(f"MR #{mr_iid}, files to scan: {list(file_contents.keys())}")

    # Step 4: Scan for prompt injection before sending to Gemini (LLM01 protection)
    injection_detected, injection_file, injection_pattern = detect_prompt_injection(file_contents)
    if injection_detected:
        logger.warning(f"Prompt injection detected in {injection_file}, pipeline stopped")
        post_mr_comment(gitlab_project_id, mr_iid, f":red_circle: **SecureAgent:** Prompt injection attempt detected in {injection_file}. Pipeline stopped for security.")
        return

    # Step 5: Gemini security analysis — retry up to 2 times if empty findings returned
    try:
        prompt = build_gemini_prompt(file_contents)
        report = call_gemini(prompt)
        retries = 0
        while not report.findings and retries < 2:
            logger.warning(f"Gemini returned empty findings, retrying, attempt {retries + 1}")
            report = call_gemini(prompt)
            retries += 1
        logger.info(f"Gemini findings: {report}")
    except Exception as e:
        logger.error(f"Gemini error: {e}")
        post_mr_comment(gitlab_project_id, mr_iid, ":red_circle: **SecureAgent Error:** Unable to complete security scan. Please retry or review manually.")
        return

    # Step 6: Handle clean result
    if not report.findings:
        post_mr_comment(gitlab_project_id, mr_iid, ":green_circle: **SecureAgent:** No vulnerabilities found. Your code is clean.")
        return

    # Step 7: Vulnerabilities found, notify developer and begin verification
    post_mr_comment(gitlab_project_id, mr_iid, ":yellow_circle: **SecureAgent:** Potential vulnerability found. Building sandbox...")

    for finding in report.findings:

        # TODO: XSS sandbox proof requires HTML rendering template (Option 2, Phase 2)
        # Currently skips live proof for XSS, still generates Issue and fix MR
        if finding.vulnerability == "Cross-Site Scripting (XSS)":
            post_mr_comment(gitlab_project_id, mr_iid,
                ":yellow_circle: **SecureAgent:** XSS vulnerability detected. Fix generated but live sandbox proof not available in current version. See GitLab Issue for details.")
            xss_proof = {**NO_PROOF, "payload_used": finding.attack_payload, "field_targeted": finding.attack_field}
            issue_url = create_gitlab_issue(gitlab_project_id, finding, xss_proof, xss_proof, 0)
            fix_mr_url = create_merge_request(gitlab_project_id, finding, branch, mr_iid, username, issue_url)
            if fix_mr_url:
                post_final_report(gitlab_project_id, mr_iid, finding, xss_proof, xss_proof, 0, issue_url, fix_mr_url)
            continue

        # Step 8: Validate Gemini's generated fix before deploying
        is_valid, reason = validate_fix(finding)
        logger.info(f"Fix validation, {finding.vulnerability}: {is_valid}, {reason}")

        if not is_valid:
            logger.warning(f"Fix rejected: {reason}, flagging for manual review")
            post_mr_comment(gitlab_project_id, mr_iid, f":red_circle: **SecureAgent:** Fix validation failed for {finding.vulnerability}, {reason}. Manual review required.")
            continue

        # Step 9: Validate Gemini's generated sandbox template (LLM05 protection)
        if hasattr(finding, 'sandbox_template') and finding.sandbox_template:
            template_valid, template_reason = validate_sandbox_template(finding.sandbox_template)
            if not template_valid:
                logger.warning(f"Sandbox template rejected: {template_reason}")
                post_mr_comment(gitlab_project_id, mr_iid, f":red_circle: **SecureAgent:** Sandbox template validation failed, {template_reason}. Manual review required.")
                continue

        try:
            # Step 10: Deploy sandbox with vulnerable code
            sandbox_url = deploy_sandbox(finding, gcp_project_id, mr_iid)
            logger.info(f"Sandbox URL: {sandbox_url}")

            # Step 11: Run attack against vulnerable sandbox, capture before proof
            before_proof = run_attack(sandbox_url, finding)

            if not before_proof["attack_succeeded"]:
                logger.warning("Attack did not succeed, vulnerability may not be exploitable in sandbox")
                post_mr_comment(gitlab_project_id, mr_iid, ":yellow_circle: **SecureAgent:** Vulnerability detected but could not be proven in sandbox. Manual review recommended.")
                continue

            logger.info("Attack succeeded, before proof captured")

            # Step 12: Deploy fix and verify it blocks the attack, capture after proof
            after_proof, attempts, needs_manual_review = iterative_fix_loop(
                finding, before_proof, gcp_project_id, mr_iid
            )

            logger.info(f"Before proof: {before_proof}")
            logger.info(f"After proof: {after_proof}")
            logger.info(f"Fix attempts: {attempts}")

            if needs_manual_review:
                post_mr_comment(gitlab_project_id, mr_iid, f":red_circle: **SecureAgent:** Could not automatically fix {finding.vulnerability} after {attempts} attempts. Manual review required.")
                continue

            # Step 13: Create GitLab Issue with full proof report
            issue_url = create_gitlab_issue(gitlab_project_id, finding, before_proof, after_proof, attempts)

            # Step 14: Commit fix and open MR on secureagent/fixes branch
            fix_mr_url = create_merge_request(gitlab_project_id, finding, branch, mr_iid, username, issue_url)

            # Step 15: Post final report summary on original developer MR
            post_final_report(gitlab_project_id, mr_iid, finding, before_proof, after_proof, attempts, issue_url, fix_mr_url)

        except Exception as e:
            logger.error(f"Pipeline error: {e}")
            post_mr_comment(gitlab_project_id, mr_iid, ":red_circle: **SecureAgent:** Pipeline error during sandbox verification. Manual review required.")
            continue


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)