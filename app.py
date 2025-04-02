import requests
import time
import json
import base64
import os
import firebase_admin
from firebase_admin import credentials, db
from dotenv import load_dotenv 
from flask import Flask
from threading import Thread

# Load environment variables from .env file
load_dotenv()

# Firebase Configuration
FIREBASE_URL = os.getenv("FIREBASE_URL")

# Construct Firebase credentials from environment variables
firebase_creds = {
    "type": os.getenv("FIREBASE_TYPE"),
    "project_id": os.getenv("FIREBASE_PROJECT_ID"),
    "private_key_id": os.getenv("FIREBASE_PRIVATE_KEY_ID"),
    "private_key": os.getenv("FIREBASE_PRIVATE_KEY").replace("\\n", "\n"),  # Handle newlines
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


# Talend API
API_URL = os.getenv("API_URL")
API_KEY = os.getenv("API_KEY")

# Azure DevOps API
AZURE_ORG = os.getenv("AZURE_ORG")
AZURE_PROJECT = os.getenv("AZURE_PROJECT")
AZURE_PIPELINE_ID = os.getenv("AZURE_PIPELINE_ID")
AZURE_API_URL = os.getenv("AZURE_API_URL")
AZURE_PAT = os.getenv("AZURE_PAT")

# Initialize Flask app
app = Flask(__name__)

# Function to trigger the Azure DevOps pipeline
def trigger_azure_pipeline():
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Basic {base64.b64encode((':' + AZURE_PAT).encode()).decode()}",
    }
    payload = json.dumps({
        "stagesToSkip": [],
        "resources": {
            "repositories": {
                "self": {
                    "refName": "refs/heads/main"
                }
            }
        }
    })

    try:
        response = requests.post(AZURE_API_URL, headers=headers, data=payload)
        response.raise_for_status()
        print("✅ Pipeline Azure DevOps triggered successfully!")
    except requests.exceptions.RequestException as e:
        print(f"❌ Error triggering pipeline: {e}")

# Function to fetch artifacts from Talend API
def fetch_artifacts():
    headers = {
        'Authorization': f'Bearer {API_KEY}',
        'Content-Type': 'application/json',
    }

    try:
        response = requests.get(API_URL, headers=headers)
        response.raise_for_status()
        data = response.json()
        return data.get('items', []) 
    except requests.exceptions.RequestException as e:
        print(f"Error fetching artifacts: {e}")
        return None

# Function to load previous artifacts from Firebase
def load_previous_artifacts():
    try:
        ref = db.reference("/previous_artifacts")
        previous_artifacts = ref.get()
        return previous_artifacts if previous_artifacts else {}
    except Exception as e:
        print(f"Error fetching previous artifacts from Firebase: {e}")
        return {}

# Function to save the current artifacts to Firebase
def save_current_artifacts(current_artifacts):
    try:
        ref = db.reference("/previous_artifacts")
        ref.set(current_artifacts)
        print("✅ Artifacts saved to Firebase successfully!")
    except Exception as e:
        print(f"❌ Error saving artifacts to Firebase: {e}")

# Function to monitor artifacts and detect new versions
def monitor_artifacts():
    previous_artifacts = load_previous_artifacts()
    first_run = len(previous_artifacts) == 0  # Check if first execution

    while True:
        current_artifacts = fetch_artifacts()
        
        if current_artifacts is not None:
            current_artifacts_data = {artifact['id']: artifact for artifact in current_artifacts}
            trigger_pipeline_flag = False
            firebase_update_flag = False

            for artifact_id, artifact in current_artifacts_data.items():
                artifact_name = artifact['name']
                artifact_versions = set(artifact['versions'])

                # Check if the artifact is new
                if artifact_id not in previous_artifacts:
                    print(f"🆕 New artifact published: {artifact_name} (ID: {artifact_id})")
                    trigger_pipeline_flag = True
                    firebase_update_flag = True
                else:
                    # Check if the artifact has new versions
                    previous_versions = set(previous_artifacts[artifact_id]['versions'])
                    new_versions = artifact_versions - previous_versions

                    if new_versions:
                        print(f"🚀 New versions for {artifact_name} (ID: {artifact_id}): {', '.join(new_versions)}")
                        trigger_pipeline_flag = True
                        firebase_update_flag = True

                # Update previous artifacts dictionary only if there's a change
                if firebase_update_flag:
                    previous_artifacts[artifact_id] = {
                        'name': artifact_name,
                        'versions': list(artifact_versions)
                    }

            # Trigger pipeline if a new artifact or version is found (except on first run)
            if trigger_pipeline_flag and not first_run:
                trigger_azure_pipeline()

            # Save current artifacts to Firebase only if there is a change
            if firebase_update_flag:
                save_current_artifacts(previous_artifacts)

        # Wait before next check
        time.sleep(30)

# Flask route to start the artifact monitoring
@app.route('/')
def start_monitoring():
    print("🚀 Starting artifact monitoring in background...")
    thread = Thread(target=monitor_artifacts)
    thread.daemon = True  
    thread.start()
    return "Artifact monitoring started in the background!"

if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)  


