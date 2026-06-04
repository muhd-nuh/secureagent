import os
import threading
from flask import Flask, request, jsonify
from dotenv import load_dotenv
import requests as http_requests
from agent.analyzer import build_gemini_prompt, call_gemini, validate_fix
from agent.sandbox import deploy_sandbox

load_dotenv()

app = Flask(__name__)

GITLAB_WEBHOOK_SECRET = os.getenv("GITLAB_WEBHOOK_SECRET")
GITLAB_TOKEN = os.getenv("GITLAB_TOKEN")


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
            # GitLab API requires forward slashes to be URL-encoded
            encoded_path = filepath.replace("/", "%2F")
            url = f"https://gitlab.com/api/v4/projects/{gitlab_project_id}/repository/files/{encoded_path}/raw?ref={branch}"
            headers = {"PRIVATE-TOKEN": GITLAB_TOKEN}
            response = http_requests.get(url, headers=headers)

            if response.status_code == 200:
                filename = os.path.basename(filepath)
                file_contents[filename] = response.text
                print(f"Fetched: {filename}")
            else:
                print(f"Warning: could not fetch {filepath} — status {response.status_code}, skipping")

        except Exception as e:
            print(f"Warning: error fetching {filepath} — {e}, skipping")

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
        print(f"Comment posted to MR #{mr_iid}")
    else:
        print(f"Failed to post comment: {response.status_code}")


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
        return jsonify({"message": "Ignored — not an MR event"}), 200

    thread = threading.Thread(target=process_pipeline, args=(payload,))
    thread.start()

    return jsonify({"message": "Pipeline triggered"}), 200


def process_pipeline(payload):
    """
    Main SecureAgent pipeline — runs in background thread.
    Stages: fetch files → analyse → validate → deploy sandbox → attack → fix → report
    """
    mr_iid = payload["object_attributes"]["iid"]
    branch = payload["object_attributes"]["source_branch"]
    gitlab_project_id = payload["project"]["id"]
    gcp_project_id = os.getenv("GOOGLE_CLOUD_PROJECT")

    # Only process MRs that are opened or updated with new commits
    action = payload["object_attributes"].get("action")
    if action not in ["open", "update"]:
        print(f"Ignored — MR action: {action}")
        return

    # Step 1: Get changed files
    changed_files = get_mr_changed_files(gitlab_project_id, mr_iid)
    print(f"Changed files: {changed_files}")

    # Step 2: Filter for supported languages only (Python + JS)
    supported_files = [
        f for f in changed_files
        if f.endswith(".py") or f.endswith(".js")
    ]

    if not supported_files:
        print("No supported files — pipeline stopped")
        return

    # Step 3: Fetch file contents from GitLab
    file_contents = fetch_file_contents(gitlab_project_id, supported_files, branch)

    if not file_contents:
        print("No file contents retrieved — pipeline stopped")
        return

    print(f"MR #{mr_iid} — files to scan: {list(file_contents.keys())}")

    # Step 4: Gemini security analysis
    try:
        prompt = build_gemini_prompt(file_contents)
        report = call_gemini(prompt)
        print(f"Gemini findings: {report}")
    except Exception as e:
        print(f"Gemini error: {e}")
        post_mr_comment(gitlab_project_id, mr_iid, ":red_circle: **SecureAgent Error:** Unable to complete security scan. Please retry or review manually.")
        return

    # Step 5: Handle clean result
    if not report.findings:
        post_mr_comment(gitlab_project_id, mr_iid, ":green_circle: **SecureAgent:** No vulnerabilities found. Your code is clean.")
        return

    # Step 6: Vulnerabilities found — notify developer and begin sandbox process
    post_mr_comment(gitlab_project_id, mr_iid, ":yellow_circle: **SecureAgent:** Potential vulnerability found. Building sandbox...")

    for finding in report.findings:
        is_valid, reason = validate_fix(finding)
        print(f"Fix validation — {finding.vulnerability}: {is_valid} — {reason}")

        if not is_valid:
            print(f"Fix rejected: {reason} — flagging for manual review")
            post_mr_comment(gitlab_project_id, mr_iid, f":red_circle: **SecureAgent:** Fix validation failed for {finding.vulnerability} — {reason}. Manual review required.")
            continue

        # Step 7: Deploy sandbox (Stage 4)
        try:
            sandbox_url = deploy_sandbox(finding, gcp_project_id, mr_iid)
            print(f"Sandbox URL: {sandbox_url}")
        except Exception as e:
            print(f"Sandbox deployment failed: {e}")
            post_mr_comment(gitlab_project_id, mr_iid, f":red_circle: **SecureAgent:** Sandbox deployment failed. Manual review required.")
            continue


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)