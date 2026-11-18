# Acquia Cloud Certbot Deployment Hooks

This repository contains a deployment hook script designed to automatically deploy Let's Encrypt SSL certificates to your Acquia Cloud environments immediately after they are successfully renewed by Certbot.

**Goal:** To ensure your Acquia Cloud sites are always running the latest, valid SSL certificates without manual intervention.

---

## Installation

This script must be placed in a specific directory recognized by Certbot for deployment hooks.

1.  **Download/Place the script:** Ensure the deployment hook script (which this README describes) is located at:
    ```bash
    /etc/letsencrypt/specific-hooks/acquia-cloud/acquia-certbot-deploy-hooks
    ```
2.  **Permissions:** Ensure the script has the necessary execution permissions.

---

## Configuration: `domains.json`

The connection details for Acquia Cloud are managed via a dedicated configuration file. This file, located at `/etc/acquia-certbot/domains.json`, maps certificate names to the required Acquia API credentials and environment UUIDs.

### Configuration Structure

The structure supports two modes:
1.  **`default_credentials`**: A single set of credentials used if a site definition doesn't specify its own.
2.  **`sites`**: A map where each key is the domain name (or certificate name).

### Example Configuration

```json
{
  "default_credentials": {
    "client_id": "8ac6cf37-b2f7-4681-8342-096f2ea56d54",
    "client_secret": "your-default-client-secret"
  },
  "sites": {
    "certificate-name": {
      "label": "Label for Acquia Cloud UI",
      "environments": [
        "4b278584-fff2-4edb-9306-e65f82c505d1"
      ]
    },
    "other-account-site.org": {
      "label": "Other Account Site",
      "credentials": {
        "client_id": "11111111-2222-4333-8444-555555555555",
        "client_secret": "site-specific-client-secret"
      },
      "environments": [
        "8afbd6bf-b2d3-4e7a-995b-b352cfb35d4b",
        "0929394f-012c-4bb2-a91a-f5b04db04f8a"
      ]
    }
  }
}
```

### Key Fields Explained:

*   **`credentials`**: API credentials specific to this site/certificate. If omitted, the hook will attempt to use `default_credentials`.
*   **`environments`**: A list of Acquia Cloud Environment UUIDs where this certificate needs to be deployed.
*   **`label`**: A descriptive name for the site, used primarily for reference in the Acquia Cloud UI.

### Setup Steps:

1.  Obtain your required API keys from Acquia Cloud.
2.  Edit `/etc/acquia-certbot/domains.json` and populate it with your necessary credentials and environment UUIDs.

---

## How to Use (Applying the Hook)

Once the configuration is in place, you must tell Certbot which certificate to apply the deployment hook to.

Use the `certbot reconfigure` command, referencing the correct certificate name and the path to the hook script:

```bash
# Example: Applying the hook to 'other-account-site.org'
sudo certbot reconfigure \
--cert-name other-account-site.org \
--deploy-hook /etc/letsencrypt/specific-hooks/acquia-cloud/acquia-certbot-deploy-hooks
```

After running this, Certbot will automatically execute the hook script whenever the certificate for `other-account-site.org` is renewed.
