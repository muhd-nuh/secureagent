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
IS_WINDOWS = platform.system() == "Windows"


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


def _build_with_docker(temp_dir: str, image_tag: str, project_id: str) -> str:
    """
    Builds and pushes sandbox image using local Docker.
    Used on Windows/local development.
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


def _build_with_cloud_build(temp_dir: str, image_tag: str, project_id: str) -> str:
    """
    Builds and pushes sandbox image using Google Cloud Build API.
    Used on Cloud Run — no local Docker needed.
    """
    import tarfile
    import uuid
    from google.cloud import storage
    from google.cloud.devtools import cloudbuild

    image_uri = f"gcr.io/{project_id}/secureagent-sandbox:{image_tag}"
    bucket_name = f"{project_id}-secureagent-builds"
    blob_name = f"source-{uuid.uuid4()}.tar.gz"

    # Create tar archive of temp_dir
    tar_path = f"/tmp/source-{uuid.uuid4()}.tar.gz"
    with tarfile.open(tar_path, "w:gz") as tar:
        tar.add(temp_dir, arcname=".")

    # Upload to GCS
    storage_client = storage.Client(project=project_id)
    try:
        bucket = storage_client.get_bucket(bucket_name)
    except Exception:
        bucket = storage_client.create_bucket(bucket_name, location="us-central1")

    blob = bucket.blob(blob_name)
    blob.upload_from_filename(tar_path)
    logger.info(f"Source uploaded to gs://{bucket_name}/{blob_name}")

    # Trigger Cloud Build
    build_client = cloudbuild.CloudBuildClient()
    build = cloudbuild.Build(
        source=cloudbuild.Source(
            storage_source=cloudbuild.StorageSource(
                bucket=bucket_name,
                object_=blob_name
            )
        ),
        steps=[
            cloudbuild.BuildStep(
                name="gcr.io/cloud-builders/docker",
                args=["build", "-t", image_uri, "."]
            )
        ],
        images=[image_uri]
    )

    operation = build_client.create_build(project_id=project_id, build=build)
    logger.info("Cloud Build triggered, waiting for completion...")
    result = operation.result(timeout=300)

    if result.status != cloudbuild.Build.Status.SUCCESS:
        raise Exception(f"Cloud Build failed with status: {result.status}")

    logger.info(f"Image built and pushed: {image_uri}")

    # Cleanup
    os.remove(tar_path)
    blob.delete()

    return image_uri


def build_and_push_image(temp_dir: str, image_tag: str, project_id: str) -> str:
    """
    Builds and pushes sandbox image.
    Uses local Docker on Windows, Cloud Build API on Linux/Cloud Run.
    """
    if IS_WINDOWS:
        return _build_with_docker(temp_dir, image_tag, project_id)
    else:
        return _build_with_cloud_build(temp_dir, image_tag, project_id)


def _deploy_with_gcloud(image_uri: str, service_name: str, project_id: str) -> str:
    """
    Deploys sandbox to Cloud Run using gcloud CLI.
    Used on Windows/local development.
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


def _deploy_with_api(image_uri: str, service_name: str, project_id: str) -> str:
    """
    Deploys sandbox to Cloud Run using Python client library.
    Used on Cloud Run — no gcloud CLI needed.
    """
    from google.cloud import run_v2
    from google.iam.v1 import iam_policy_pb2, policy_pb2

    logger.info(f"Deploying sandbox to Cloud Run: {service_name}")

    region = os.getenv("CLOUD_RUN_REGION", "us-central1")
    client = run_v2.ServicesClient()
    parent = f"projects/{project_id}/locations/{region}"
    service_path = f"{parent}/services/{service_name}"

    service = run_v2.Service(
        template=run_v2.RevisionTemplate(
            containers=[
                run_v2.Container(
                    image=image_uri,
                    ports=[run_v2.ContainerPort(container_port=8080)],
                    resources=run_v2.ResourceRequirements(
                        limits={"memory": "512Mi", "cpu": "1"}
                    )
                )
            ],
            scaling=run_v2.RevisionScaling(
                min_instance_count=0,
                max_instance_count=1
            )
        )
    )

    try:
        # Update existing service if it exists
        existing = client.get_service(name=service_path)
        service.name = service_path
        service.etag = existing.etag
        operation = client.update_service(service=service)
        logger.info("Updating existing sandbox service...")
    except Exception:
        # Create new service — name must NOT be set on create
        service.name = ""
        operation = client.create_service(
            parent=parent,
            service=service,
            service_id=service_name
        )
        logger.info("Creating new sandbox service...")

    result = operation.result(timeout=300)
    url = result.uri

    # Allow unauthenticated access to sandbox
    try:
        iam_client = run_v2.ServicesClient()
        iam_client.set_iam_policy(
            request=iam_policy_pb2.SetIamPolicyRequest(
                resource=service_path,
                policy=policy_pb2.Policy(
                    bindings=[
                        policy_pb2.Binding(
                            role="roles/run.invoker",
                            members=["allUsers"]
                        )
                    ]
                )
            )
        )
    except Exception as e:
        logger.warning(f"Could not set IAM policy: {e}")

    logger.info(f"Sandbox live at: {url}")
    return url


def deploy_to_cloud_run(image_uri: str, service_name: str, project_id: str) -> str:
    """
    Deploys sandbox to Cloud Run.
    Uses gcloud CLI on Windows, Python API on Linux/Cloud Run.
    """
    if IS_WINDOWS:
        return _deploy_with_gcloud(image_uri, service_name, project_id)
    else:
        return _deploy_with_api(image_uri, service_name, project_id)


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