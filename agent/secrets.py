import os
from google.cloud import secretmanager
from dotenv import load_dotenv
from agent.logger import get_logger

load_dotenv()

logger = get_logger("secrets")

# Cache secrets to avoid repeated API calls within the same session
_secret_cache = {}


def get_secret(secret_name: str) -> str:
    """
    Fetches a secret from Google Cloud Secret Manager.
    Falls back to environment variable if Secret Manager is unavailable.
    Caches results to avoid repeated API calls within the same session.
    """
    if secret_name in _secret_cache:
        return _secret_cache[secret_name]

    project_id = os.getenv("GOOGLE_CLOUD_PROJECT")

    try:
        client = secretmanager.SecretManagerServiceClient()
        name = f"projects/{project_id}/secrets/{secret_name}/versions/latest"
        response = client.access_secret_version(request={"name": name})
        value = response.payload.data.decode("utf-8").strip()
        _secret_cache[secret_name] = value
        logger.info(f"Secret fetched from Secret Manager: {secret_name}")
        return value
    except Exception as e:
        logger.warning(f"Secret Manager unavailable for {secret_name}, falling back to env var: {e}")
        return os.getenv(secret_name)