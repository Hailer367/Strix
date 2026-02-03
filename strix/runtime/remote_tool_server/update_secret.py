"""
Module to update GitHub secrets via API using SERVER_TOKEN
"""
import sys
import json
import base64
import requests
from typing import Optional


def update_secret(
    server_token: str,  # This is the SERVER_TOKEN that has special permissions
    owner: str,
    repo: str,
    secret_name: str,
    secret_value: str  # This is the AES-256-CBC encrypted and base64-encoded value
) -> bool:
    """
    Update a GitHub repository secret using the SERVER_TOKEN that has special permissions
    to update the QWEN_TOKENS secret.

    Args:
        server_token: Special token (SERVER_TOKEN) that has permissions to update QWEN_TOKENS
        owner: Repository owner/organization name
        repo: Repository name
        secret_name: Name of the secret to update (should be QWEN_TOKENS)
        secret_value: Value of the secret to set (AES-256-CBC encrypted and base64 encoded)

    Returns:
        True if successful, False otherwise
    """

    headers = {
        "Authorization": f"Bearer {server_token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "Strix-Secret-Updater"
    }

    # The SERVER_TOKEN has special permissions to update QWEN_TOKENS directly
    # We don't need to get a public key since the encryption was already done by the workflow
    secret_url = f"https://api.github.com/repos/{owner}/{repo}/actions/secrets/{secret_name}"

    # Prepare the payload - the secret_value is already AES-256-CBC encrypted and base64 encoded
    payload = {
        "encrypted_value": secret_value  # Our AES-encrypted and base64-encoded value
        # Note: We're not including key_id since the SERVER_TOKEN handles this differently
    }

    try:
        response = requests.put(secret_url, headers=headers, json=payload)

        if response.status_code == 201 or response.status_code == 204:
            print(f"✅ Secret '{secret_name}' updated successfully using SERVER_TOKEN")
            return True
        else:
            print(f"❌ Failed to update secret: {response.status_code} - {response.text}")
            print("💡 The SERVER_TOKEN might not have the right permissions or the encrypted value format might be incorrect.")
            return False

    except requests.exceptions.RequestException as e:
        print(f"❌ Request error: {str(e)}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {str(e)}")
        return False


def main():
    """Main function to run from command line"""
    if len(sys.argv) != 6:
        print("Usage: python -m strix.runtime.remote_tool_server.update_secret <server_token> <owner> <repo> <secret_name> <secret_value>")
        sys.exit(1)

    server_token = sys.argv[1]  # This is the SERVER_TOKEN
    owner = sys.argv[2]
    repo = sys.argv[3]
    secret_name = sys.argv[4]
    secret_value = sys.argv[5]

    success = update_secret(server_token, owner, repo, secret_name, secret_value)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()