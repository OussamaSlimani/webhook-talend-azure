import requests
import time
import json
import base64
import os
import firebase_admin
import logging
from firebase_admin import credentials, db
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Firebase Configuration
FIREBASE_URL = os.getenv("FIREBASE_URL")

firebase_creds = {
    "type": os.getenv("FIREBASE_TYPE"),
    "project_id": os.getenv("FIREBASE_PROJECT_ID"),
    "private_key_id": os.getenv("FIREBASE_PRIVATE_KEY_ID"),
    "private_key": os.getenv("FIREBASE_PRIVATE_KEY").replace("\\n", "\n"),
    "client_email": os.getenv("FIREBASE_CLIENT_EMAIL"),
    "client_id": os.getenv("FIREBASE_CLIENT_ID"),
    "auth_uri": os.getenv("FIREBASE_AUTH_URI"),
    "token_uri": os.getenv("FIREBASE_TOKEN_URI"),
    "auth_provider_x509_cert_url": os.getenv("FIREBASE_AUTH_PROVIDER_CERT_URL"),
    "client_x509_cert_url": os.getenv("FIREBASE_CLIENT_CERT_URL"),
    "universe_domain": os.getenv("FIREBASE_UNIVERSE_DOMAIN"),
}

# Initialize Firebase
if not firebase_admin._apps:
    cred = credentials.Certificate(firebase_creds)
    firebase_admin.initialize_app(cred, {"databaseURL": FIREBASE_URL})

# API and Pipeline Configuration
API_URL = os.getenv("API_URL")
API_KEY = os.getenv("API_KEY")
AZURE_API_URL = os.getenv("AZURE_API_URL")
AZURE_PAT = os.getenv("AZURE_PAT")

def trigger_azure_pipeline():
    """Triggers the Azure DevOps pipeline."""
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Basic {base64.b64encode((':' + AZURE_PAT).encode()).decode()}",
    }
    payload = json.dumps({
        "stagesToSkip": [],
        "resources": {"repositories": {"self": {"refName": "refs/heads/main"}}}
    })

    try:
        response = requests.post(AZURE_API_URL, headers=headers, data=payload)
        response.raise_for_status()
        logger.info("✅ Azure DevOps pipeline triggered successfully!")
    except requests.exceptions.RequestException as e:
        logger.error(f"❌ Error triggering pipeline: {e}")

def fetch_artifacts():
    """Fetches the latest artifacts from the Talend API."""
    headers = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}

    try:
        response = requests.get(API_URL, headers=headers)
        response.raise_for_status()
        return response.json().get('items', [])
    except requests.exceptions.RequestException as e:
        logger.error(f"❌ Error fetching artifacts: {e}")
        return None

def load_previous_artifacts():
    """Loads previously stored artifacts from Firebase."""
    try:
        return db.reference("/previous_artifacts").get() or {}
    except Exception as e:
        logger.error(f"❌ Error loading previous artifacts: {e}")
        return {}

def save_current_artifacts(artifact_id, artifact_data):
    """Updates Firebase with new artifact data."""
    try:
        db.reference(f"/previous_artifacts/{artifact_id}").set(artifact_data)
        logger.info(f"✅ Updated Firebase for artifact {artifact_id}")
    except Exception as e:
        logger.error(f"❌ Error saving artifact {artifact_id}: {e}")

def monitor_artifacts():
    """Continuously monitors artifacts and triggers the pipeline when new versions are detected."""
    try:
        previous_artifacts = load_previous_artifacts()
        current_artifacts = fetch_artifacts()

        no_new_versions = True

        for artifact in current_artifacts:
            artifact_id = artifact['id']
            artifact_name = artifact['name']
            artifact_versions = set(artifact['versions'])

            if artifact_id not in previous_artifacts:
                logger.info(f"🆕 New artifact detected: {artifact_name} (ID: {artifact_id})")
                trigger_azure_pipeline()
                save_current_artifacts(artifact_id, {"name": artifact_name, "versions": list(artifact_versions)})
                no_new_versions = False
            else:
                previous_versions = set(previous_artifacts[artifact_id].get("versions", []))
                new_versions = artifact_versions - previous_versions

                if new_versions:
                    logger.info(f"🚀 New versions for {artifact_name}: {', '.join(new_versions)}")
                    trigger_azure_pipeline()
                    save_current_artifacts(artifact_id, {"name": artifact_name, "versions": list(artifact_versions)})
                    no_new_versions = False

        if no_new_versions:
            logger.info("🙈 There is no update")


    except Exception as e:
        logger.error(f"❌ Error in monitoring loop: {e}")

if __name__ == "__main__":
    logger.info("🔄 Starting artifact monitoring...")
    while True:
        monitor_artifacts()  
        time.sleep(30)
