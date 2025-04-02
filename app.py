import requests
import time
import json
import base64
import os
import firebase_admin
import logging
from firebase_admin import credentials, db
from dotenv import load_dotenv
from flask import Flask
from threading import Thread, Event

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

# Initialize Flask app
app = Flask(__name__)

# Stop event for monitoring thread
stop_event = Event()

def trigger_azure_pipeline():
    """Triggers the Azure DevOps pipeline."""
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Basic {base64.b64encode((':' + AZURE_PAT).encode()).decode()}"
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
    previous_artifacts = load_previous_artifacts()
    local_cache = {k: set(v["versions"]) for k, v in previous_artifacts.items()}  # Local cache
    
    while not stop_event.is_set():
        try:
            current_artifacts = fetch_artifacts()
            if current_artifacts is None:
                continue

            for artifact in current_artifacts:
                artifact_id = artifact['id']
                artifact_name = artifact['name']
                artifact_versions = set(artifact['versions'])
                
                if artifact_id not in local_cache:
                    logger.info(f"🆕 New artifact detected: {artifact_name} (ID: {artifact_id})")
                    trigger_azure_pipeline()
                    save_current_artifacts(artifact_id, {"name": artifact_name, "versions": list(artifact_versions)})
                    local_cache[artifact_id] = artifact_versions
                else:
                    previous_versions = local_cache[artifact_id]
                    new_versions = artifact_versions - previous_versions

                    if new_versions:
                        new_versions_list = list(new_versions)
                        logger.info(f"🚀 New versions for {artifact_name}: {', '.join(new_versions_list)}")
                        trigger_azure_pipeline()
                        save_current_artifacts(artifact_id, {"name": artifact_name, "versions": list(artifact_versions)})
                        local_cache[artifact_id] = artifact_versions

            time.sleep(30)
        except Exception as e:
            logger.error(f"❌ Error in monitoring loop: {e}")

# Flask routes
@app.route('/start')
def start_monitoring():
    """Starts the artifact monitoring in the background."""
    if not stop_event.is_set():
        logger.info("🚀 Starting artifact monitoring...")
        thread = Thread(target=monitor_artifacts, daemon=True)
        thread.start()
        return "Artifact monitoring started!"

@app.route('/stop')
def stop_monitoring():
    """Stops the artifact monitoring."""
    stop_event.set()
    return "Artifact monitoring has been stopped!"

if __name__ == "__main__":
    # Auto-start monitoring when the app runs
    logger.info("🔄 Auto-starting artifact monitoring...")
    monitoring_thread = Thread(target=monitor_artifacts, daemon=True)
    monitoring_thread.start()
    app.run(debug=True, use_reloader=False)