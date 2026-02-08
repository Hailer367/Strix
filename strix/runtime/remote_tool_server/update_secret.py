"""Script to update GitHub secret via API."""

import base64
import sys
from typing import Any

import requests
from nacl import encoding, public


def encrypt_secret(public_key: str, secret_value: str) -> str:
    """Encrypt a secret using the repository's public key."""
    public_key_obj = public.PublicKey(
        public_key.encode("utf-8"), encoding.Base64Encoder()
    )
    sealed_box = public.SealedBox(public_key_obj)
    encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
    return base64.b64encode(encrypted).decode("utf-8")


def get_public_key(token: str, owner: str, repo: str) -> dict[str, Any]:
    """Get repository public key for secret encryption."""
    url = f"https://api.github.com/repos/{owner}/{repo}/actions/secrets/public-key"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }

    response = requests.get(url, headers=headers, timeout=10)
    response.raise_for_status()
    return response.json()


def verify_token_permissions(token: str, owner: str, repo: str) -> dict[str, Any]:
    """Verify the token has necessary permissions to update secrets."""
    # First, check if token is valid and get repo info
    repo_url = f"https://api.github.com/repos/{owner}/{repo}"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }

    response = requests.get(repo_url, headers=headers, timeout=10)

    if response.status_code == 404:
        raise PermissionError(
            f"Repository '{owner}/{repo}' not found or token cannot access it. "
            "Ensure the token has 'repo' (private) or 'public_repo' (public) scope."
        )
    elif response.status_code == 401:
        raise PermissionError(
            "Token is invalid or expired. Please check your SERVER_TOKEN secret."
        )

    response.raise_for_status()
    repo_data = response.json()

    # Check if we can access the public key endpoint (indicates secrets permission)
    public_key_url = f"https://api.github.com/repos/{owner}/{repo}/actions/secrets/public-key"
    pk_response = requests.get(public_key_url, headers=headers, timeout=10)

    if pk_response.status_code == 403:
        raise PermissionError(
            "Token lacks permission to manage repository secrets. "
            "Ensure your SERVER_TOKEN has 'repo' scope (for private repos) or "
            "'public_repo' scope (for public repos). Also verify the token owner "
            "has admin access to this repository."
        )
    elif pk_response.status_code == 404:
        raise PermissionError(
            "Actions secrets API not accessible. Ensure GitHub Actions is enabled "
            f"for repository '{owner}/{repo}'."
        )

    pk_response.raise_for_status()

    return repo_data


def update_secret(
    token: str, owner: str, repo: str, secret_name: str, secret_value: str
) -> None:
    """Update a GitHub secret."""
    # Verify token permissions first
    verify_token_permissions(token, owner, repo)

    # Get public key
    public_key_data = get_public_key(token, owner, repo)
    public_key = public_key_data["key"]
    key_id = public_key_data["key_id"]

    # Encrypt secret
    encrypted_value = encrypt_secret(public_key, secret_value)

    # Update secret
    url = f"https://api.github.com/repos/{owner}/{repo}/actions/secrets/{secret_name}"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }
    data = {
        "encrypted_value": encrypted_value,
        "key_id": key_id,
    }

    response = requests.put(url, headers=headers, json=data, timeout=10)

    if response.status_code == 403:
        raise PermissionError(
            f"403 Forbidden: Cannot update secret '{secret_name}'. "
            "Common causes:\n"
            "  1. Token lacks 'repo' or 'public_repo' scope\n"
            "  2. Token owner doesn't have admin access to this repository\n"
            "  3. Repository has branch protection rules preventing secret updates\n"
            "  4. Token is from an app/bot that doesn't have repository secrets permission\n"
            "\nTo fix: Create a Personal Access Token (classic) with 'repo' scope at:\n"
            "  https://github.com/settings/tokens"
        )

    response.raise_for_status()
    print(f"✓ Successfully updated secret '{secret_name}'")


def main() -> None:
    """Main function."""
    if len(sys.argv) < 6:
        print("Usage: update_secret.py <token> <owner> <repo> <secret_name> <secret_value>")
        print("\nEnvironment variables:")
        print("  GITHUB_TOKEN - Alternative way to provide the token")
        sys.exit(1)

    token = sys.argv[1]
    owner = sys.argv[2]
    repo = sys.argv[3]
    secret_name = sys.argv[4]
    secret_value = sys.argv[5]

    try:
        update_secret(token, owner, repo, secret_name, secret_value)
    except PermissionError as e:
        print(f"Permission Error: {e}")
        sys.exit(1)
    except requests.exceptions.HTTPError as e:
        print(f"HTTP Error updating secret: {e}")
        if e.response is not None:
            print(f"Response: {e.response.text}")
        sys.exit(1)
    except Exception as e:
        print(f"Error updating secret: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
