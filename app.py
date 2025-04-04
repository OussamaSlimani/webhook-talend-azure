import requests
import time
import json
import base64
import os
import firebase_admin
import logging
import threading
from flask import Flask
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

# Talend
TALEND_API_URL = os.getenv("TALEND_API_URL")
TALEND_API_KEY = os.getenv("TALEND_API_KEY")

# Azure DevOps
AZURE_ORG = os.getenv("AZURE_ORG")
AZURE_PROJECT = os.getenv("AZURE_PROJECT")
AZURE_PIPELINE_ID = os.getenv("AZURE_PIPELINE_ID")
AZURE_PAT = os.getenv("AZURE_PAT")

# Construct AZURE API URL
AZURE_API_URL = f"https://dev.azure.com/{AZURE_ORG}/{AZURE_PROJECT}/_apis/pipelines/{AZURE_PIPELINE_ID}/runs?api-version=7.1-preview.1"

app = Flask(__name__)

# Global flag to control the thread
monitoring_thread = None
monitoring_active = False

def trigger_azure_pipeline():
    """Triggers the Azure DevOps pipeline."""
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Basic {base64.b64encode((':' + AZURE_PAT).encode()).decode()}",
    }
    payload = json.dumps({})

    try:
        response = requests.post(AZURE_API_URL, headers=headers, data=payload)
        response.raise_for_status()
        logger.info("✅ Azure DevOps pipeline triggered successfully!")
    except requests.exceptions.RequestException as e:
        logger.error(f"❌ Error triggering pipeline: {e}")

def fetch_artifacts():
    """Fetches the latest artifacts from the Talend API."""
    headers = {"Authorization": f"Bearer {TALEND_API_KEY}", "Content-Type": "application/json"}

    try:
        response = requests.get(TALEND_API_URL, headers=headers)
        response.raise_for_status()
        return response.json().get('items', [])
    except requests.exceptions.RequestException as e:
        logger.error(f"❌ Error fetching artifacts: {e}")
        return None

def read_from_firebase(database):
    """Reads the stored data from a specific Firebase database reference."""
    try:
        # Fetch data from Firebase, returning an empty dict if None is returned
        previous_artifacts = db.reference(f"/{database}").get() or {}
        return previous_artifacts
    except Exception as e:
        logger.error(f"❌ Error reading from Firebase: {e}")
        return {}


def save_to_firebase(artifact_id, artifact_data):
    """Saves the current artifacts to Firebase."""
    try:
        db.reference(f"/previous_artifacts/{artifact_id}").set(artifact_data)
        logger.info(f"✅ Updated Firebase for artifact {artifact_id}")
    except Exception as e:
        logger.error(f"❌ Error saving artifact {artifact_id}: {e}")

def monitor_artifacts():
    """Monitors the artifacts and triggers the pipeline if there are new versions."""
    try:
        previous_artifacts = read_from_firebase("previous_artifacts")
        current_artifacts = fetch_artifacts()

        no_new_versions = True

        engines = read_from_firebase("engines")
        workspace_set = {data['DynamicEngineWorkspace']['name'] for env, data in engines.items() if 'DynamicEngineWorkspace' in data}
        env_name_set = {data['DynamicEngineEnv']['name'] for env, data in engines.items() if 'DynamicEngineEnv' in data}


        for artifact in current_artifacts:
            artifact_id = artifact['id']
            artifact_name = artifact['name']
            artifact_versions = set(artifact['versions'])
            workspace_name = artifact['workspace']['name']
            environment_name = artifact['workspace']['environment']['name']

            if(workspace_name not in workspace_set or environment_name not in env_name_set):
                logger.info(f"↪️ Ignoring artifact {artifact_name} (ID: {artifact_id}) due to workspace/environment mismatch.")
                continue

            if artifact_id not in previous_artifacts:
                logger.info(f"🆕 New artifact detected: {artifact_name} (ID: {artifact_id})")
                trigger_azure_pipeline()
                save_to_firebase(artifact_id, {"name": artifact_name, "versions": list(artifact_versions)})
                no_new_versions = False
            else:
                previous_versions = set(previous_artifacts[artifact_id].get("versions", []))
                new_versions = artifact_versions - previous_versions

                if new_versions:
                    logger.info(f"🚀 New versions for {artifact_name}: {', '.join(new_versions)}")
                    trigger_azure_pipeline()
                    save_to_firebase(artifact_id, {"name": artifact_name, "versions": list(artifact_versions)})
                    no_new_versions = False

        if no_new_versions:
            logger.info("🙈 There is no update")

    except Exception as e:
        logger.error(f"❌ Error in monitoring loop: {e}")

def start_monitoring():
    """Starts the artifact monitoring in a new thread."""
    global monitoring_thread, monitoring_active
    if not monitoring_active:
        monitoring_active = True
        monitoring_thread = threading.Thread(target=run_monitoring)
        monitoring_thread.start()
        logger.info("🔄 Monitoring started!")

def stop_monitoring():
    """Stops the artifact monitoring."""
    global monitoring_active
    if monitoring_active:
        monitoring_active = False
        logger.info("🛑 Monitoring stopped!")

def run_monitoring():
    """Runs the monitoring process in a loop."""
    while monitoring_active:
        monitor_artifacts()
        time.sleep(30)

@app.route('/start', methods=['GET'])
def start():
    start_monitoring()
    return "Monitoring started!", 200

@app.route('/stop', methods=['GET'])
def stop():
    stop_monitoring()
    return "Monitoring stopped!", 200

if __name__ == '__main__':
    app.run(debug=True)
