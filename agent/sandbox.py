import os
import shutil
import tempfile
import subprocess
import time
import platform
from dotenv import load_dotenv
from agent.logger import get_logger
from agent.secrets import get_secret

load_dotenv()

logger = get_logger("sandbox")

# Use .cmd extension on Windows, gcloud is a shell script on Linux/Mac
GCLOUD_CMD = "gcloud.cmd" if platform.system() == "Windows" else "gcloud"


def inject_vulnerable_code(vulnerable_code: str, sandbox_template: str = None, attack_field: str = "username") -> str:
    """
    Creates a temporary working directory with the sandbox app ready for Docker build.
    Prefers Gemini's dynamically generated template over the static fallback.
    The attack_field parameter ensures the sandbox uses the correct form field name.
    Returns the temp directory path.
    """
    temp_dir = tempfile.mkdtemp()
    templates_dir = os.path.join(os.path.dirname(__file__), '..', 'templates')

    # Dockerfile is the same regardless of which template is used
    shutil.copy(os.path.join(templates_dir, 'Dockerfile'), temp_dir)

    if sandbox_template:
        # Gemini sometimes defaults to 'username' even when the vulnerable field differs.
        # Replace it with the actual attack field to keep the sandbox accurate.
        if attack_field and attack_field != "username":
            sandbox_template = sandbox_template.replace(
                'request.form.get("username")',
                f'request.form.get("{attack_field}")'
            )
        with open(os.path.join(temp_dir, 'vulnerable_app.py'), 'w') as f:
            f.write(sandbox_template)
        logger.info(f"Gemini-generated sandbox template written to: {temp_dir}")
    else:
        # Static fallback, injects the single vulnerable line into the harness template
        template_path = os.path.join(templates_dir, 'vulnerable_app.py')
        with open(template_path, 'r') as f:
            template_content = f.read()

        cleaned_code = vulnerable_code.strip()
        injected_content = template_content.replace(
            "    # VULNERABLE_CODE_PLACEHOLDER",
            f"    {cleaned_code}"
        )

        with open(os.path.join(temp_dir, 'vulnerable_app.py'), 'w') as f:
            f.write(injected_content)
        logger.info(f"Static template with injected code written to: {temp_dir}")

    return temp_dir


def build_and_push_image(temp_dir: str, image_tag: str, project_id: str) -> str:
    """
    Builds a Docker image from the temp directory and pushes it to
    Google Container Registry. Returns the full image URI.
    """
    image_uri = f"gcr.io/{project_id}/secureagent-sandbox:{image_tag}"

    logger.info(f"Building Docker image: {image_uri}")
    build_result = subprocess.run(
        ["docker", "build", "-t", image_uri, temp_dir],
        capture_output=True,
        text=True
    )

    if build_result.returncode != 0:
        raise Exception(f"Docker build failed: {build_result.stderr}")

    logger.info("Docker image built successfully")

    logger.info("Pushing image to GCR...")
    push_result = subprocess.run(
        ["docker", "push", image_uri],
        capture_output=True,
        text=True
    )

    if push_result.returncode != 0:
        raise Exception(f"Docker push failed: {push_result.stderr}")

    logger.info(f"Image pushed: {image_uri}")
    return image_uri


def deploy_to_cloud_run(image_uri: str, service_name: str, project_id: str) -> str:
    """
    Deploys the sandbox image to Cloud Run as an ephemeral test environment.
    Each sandbox uses a unique service name based on MR ID to avoid conflicts.
    gcloud outputs the service URL to stderr, not stdout, so we parse stderr.
    Returns the live sandbox URL.
    """
    logger.info(f"Deploying sandbox to Cloud Run: {service_name}")

    deploy_result = subprocess.run(
        [
            GCLOUD_CMD, "run", "deploy", service_name,
            "--image", image_uri,
            "--platform", "managed",
            "--region", get_secret("CLOUD_RUN_REGION") or "us-central1",
            "--allow-unauthenticated",
            "--port", "8080",
            "--project", project_id,
            "--quiet"
        ],
        capture_output=True,
        text=True
    )

    if deploy_result.returncode != 0:
        raise Exception(f"Cloud Run deploy failed: {deploy_result.stderr}")

    for line in deploy_result.stderr.split("\n"):
        if "https://" in line and "Service URL:" in line:
            url = line.strip().split("Service URL: ")[-1]
            logger.info(f"Sandbox live at: {url}")
            return url

    raise Exception("Could not extract Cloud Run URL from deployment output")


def deploy_sandbox(finding, project_id: str, mr_iid: str) -> str:
    """
    Orchestrates the full sandbox deployment for a single finding.
    Uses Gemini's generated sandbox template if available, falls back to static template.
    project_id is the GCP project ID, not the GitLab project ID.
    Returns the sandbox URL once live.
    """
    service_name = f"secureagent-sandbox-mr{mr_iid}"
    image_tag = f"mr{mr_iid}"

    sandbox_template = getattr(finding, 'sandbox_template', None)

    temp_dir = None
    try:
        temp_dir = inject_vulnerable_code(
            finding.vulnerable_code,
            sandbox_template,
            getattr(finding, 'attack_field', 'username')
        )
        image_uri = build_and_push_image(temp_dir, image_tag, project_id)
        sandbox_url = deploy_to_cloud_run(image_uri, service_name, project_id)

        # Brief wait to ensure the service is fully ready before attacks begin
        logger.info("Waiting for sandbox to warm up...")
        time.sleep(10)

        return sandbox_url

    finally:
        # Always clean up temp dir regardless of success or failure
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)