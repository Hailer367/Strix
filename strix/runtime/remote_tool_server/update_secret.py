"""
Module to update GitHub secrets via API
"""
import sys
import json
import base64
import requests
from typing import Optional


def update_secret(
    token: str,
    owner: str,
    repo: str,
    secret_name: str,
    secret_value: str
) -> bool:
    """
    Update a GitHub repository secret using the GitHub API
    
    Args:
        token: GitHub personal access token with repo permissions
        owner: Repository owner/organization name
        repo: Repository name
        secret_name: Name of the secret to update
        secret_value: Value of the secret to set
        
    Returns:
        True if successful, False otherwise
    """
    
    # First, get the public key for encrypting the secret
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "Strix-Secret-Updater"
    }
    
    pub_key_url = f"https://api.github.com/repos/{owner}/{repo}/actions/secrets/public-key"
    
    try:
        response = requests.get(pub_key_url, headers=headers)
        if response.status_code != 200:
            print(f"❌ Failed to get public key: {response.status_code} - {response.text}")
            return False
            
        pub_key_data = response.json()
        key_id = pub_key_data["key_id"]
        public_key = pub_key_data["key"]
        
        # Note: In a real implementation, we would encrypt the secret_value
        # with the public key using libsodium. For this workflow, the value
        # is already encrypted and base64-encoded, so we'll use it as-is.
        
        # Update the secret
        secret_url = f"https://api.github.com/repos/{owner}/{repo}/actions/secrets/{secret_name}"
        payload = {
            "encrypted_value": secret_value,  # Already encrypted and base64 encoded
            "key_id": key_id
        }
        
        response = requests.put(secret_url, headers=headers, json=payload)
        
        if response.status_code == 201 or response.status_code == 204:
            print(f"✅ Secret '{secret_name}' updated successfully")
            return True
        else:
            print(f"❌ Failed to update secret: {response.status_code} - {response.text}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Request error: {str(e)}")
        return False
    except KeyError as e:
        print(f"❌ Missing key in response: {str(e)}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {str(e)}")
        return False


def main():
    """Main function to run from command line"""
    if len(sys.argv) != 6:
        print("Usage: python -m strix.runtime.remote_tool_server.update_secret <token> <owner> <repo> <secret_name> <secret_value>")
        sys.exit(1)
        
    token = sys.argv[1]
    owner = sys.argv[2]
    repo = sys.argv[3]
    secret_name = sys.argv[4]
    secret_value = sys.argv[5]
    
    success = update_secret(token, owner, repo, secret_name, secret_value)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()