import os
import shutil
import tempfile
import subprocess
import time
import platform
from dotenv import load_dotenv

load_dotenv()

# Use .cmd extension on Windows — gcloud is a shell script on Linux/Mac
GCLOUD_CMD = "gcloud.cmd" if platform.system() == "Windows" else "gcloud"


def inject_vulnerable_code(vulnerable_code: str) -> str:
    """
    Creates a temporary working directory with the harness template
    and injects the developer's actual vulnerable code in place of the placeholder.
    Returns the path to the temp directory ready for Docker build.
    """
    temp_dir = tempfile.mkdtemp()
    templates_dir = os.path.join(os.path.dirname(__file__), '..', 'templates')

    # Copy Dockerfile into temp dir
    shutil.copy(os.path.join(templates_dir, 'Dockerfile'), temp_dir)

    # Read the harness template and inject vulnerable code
    template_path = os.path.join(templates_dir, 'vulnerable_app.py')
    with open(template_path, 'r') as f:
        template_content = f.read()

    injected_content = template_content.replace(
        "# VULNERABLE_CODE_PLACEHOLDER",
        vulnerable_code
    )

    with open(os.path.join(temp_dir, 'vulnerable_app.py'), 'w') as f:
        f.write(injected_content)

    print(f"Vulnerable code injected — temp dir: {temp_dir}")
    return temp_dir


def build_and_push_image(temp_dir: str, image_tag: str, project_id: str) -> str:
    """
    Builds a Docker image from the temp directory and pushes it to
    Google Container Registry. Returns the full image URI.
    """
    image_uri = f"gcr.io/{project_id}/secureagent-sandbox:{image_tag}"

    print(f"Building Docker image: {image_uri}")
    build_result = subprocess.run(
        ["docker", "build", "-t", image_uri, temp_dir],
        capture_output=True,
        text=True
    )

    if build_result.returncode != 0:
        raise Exception(f"Docker build failed: {build_result.stderr}")

    print("Docker image built successfully")

    print("Pushing image to GCR...")
    push_result = subprocess.run(
        ["docker", "push", image_uri],
        capture_output=True,
        text=True
    )

    if push_result.returncode != 0:
        raise Exception(f"Docker push failed: {push_result.stderr}")

    print(f"Image pushed: {image_uri}")
    return image_uri


def deploy_to_cloud_run(image_uri: str, service_name: str, project_id: str) -> str:
    """
    Deploys the sandbox image to Cloud Run.
    Each sandbox gets a unique service name based on the MR ID to avoid conflicts.
    Returns the live sandbox URL.
    """
    print(f"Deploying sandbox to Cloud Run: {service_name}")

    deploy_result = subprocess.run(
        [
            GCLOUD_CMD, "run", "deploy", service_name,
            "--image", image_uri,
            "--platform", "managed",
            "--region", os.getenv("CLOUD_RUN_REGION", "us-central1"),
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

    # gcloud outputs the service URL to stderr, not stdout
    for line in deploy_result.stderr.split("\n"):
        if "https://" in line and "Service URL:" in line:
            url = line.strip().split("Service URL: ")[-1]
            print(f"Sandbox live at: {url}")
            return url

    raise Exception("Could not extract Cloud Run URL from deployment output")


def deploy_sandbox(finding, project_id: str, mr_iid: str) -> str:
    """
    Orchestrates the full sandbox deployment flow for a single finding.
    project_id here is the GCP project ID passed from main.py.
    Returns the sandbox URL once live.
    """
    service_name = f"secureagent-sandbox-mr{mr_iid}"
    image_tag = f"mr{mr_iid}"

    temp_dir = None
    try:
        temp_dir = inject_vulnerable_code(finding.vulnerable_code)
        image_uri = build_and_push_image(temp_dir, image_tag, project_id)
        sandbox_url = deploy_to_cloud_run(image_uri, service_name, project_id)

        print("Waiting for sandbox to warm up...")
        time.sleep(10)

        return sandbox_url

    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)