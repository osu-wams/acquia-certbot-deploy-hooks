//! Certbot deploy hook for uploading and activating SSL certificates on Acquia Cloud.
//!
//! # Configuration (`/etc/acquia-certbot/domains.json`)
//!
//! Override the default path with `ACQUIA_CONFIG_PATH`. Site keys must match the
//! Certbot lineage directory name (`basename "$RENEWED_LINEAGE"`), which corresponds
//! to `--cert-name` or the primary domain of the certificate.
//!
//! ```json
//! {
//!   "default_credentials": {
//!     "client_id": "63dad278-4f6b-4dde-8e4b-ad0696d1b934",
//!     "client_secret": "your-default-client-secret"
//!   },
//!   "sites": {
//!     "certificate-name": {
//!       "label": "Label for Acquia Cloud UI",
//!       "environments": [
//!         "106443-8026ebdc-b0d9-4095-8036-7d2dc8c26974"
//!       ]
//!     },
//!     "other-account-site.org": {
//!       "label": "Other Account Site",
//!       "credentials": {
//!         "client_id": "11111111-2222-4333-8444-555555555555",
//!         "client_secret": "site-specific-client-secret"
//!       },
//!       "environments": [
//!         "106443-1a2b3c4d-5e6f-4789-9abc-def012345678",
//!         "106443-9f8e7d6c-5b4a-4321-8fed-cba987654321"
//!       ]
//!     }
//!   }
//! }
//! ```
use chrono::{DateTime, FixedOffset, Local, Utc};
use oauth2::basic::BasicClient;
use oauth2::{AuthType, ClientId, ClientSecret, TokenResponse, TokenUrl, reqwest};
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderMap};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};
use std::{env, fs, process, thread};

// Flags that we will need.
struct CliArgs {
    env_uuid: String,
}
// Acquia nests the items under tne _embedded object
#[derive(Deserialize, Debug)]
struct AcquiaCollection<T> {
    #[serde(rename = "_embedded")]
    embedded: EmbeddedItems<T>,
}
// The array of Items inside the _embedded object.
#[derive(Deserialize, Debug)]
struct EmbeddedItems<T> {
    items: Vec<T>,
}
// Certificate Object
#[derive(Deserialize, Debug)]
struct Certificate {
    id: u64,
    label: Option<String>,
    certificate: Option<String>,
    private_key: Option<String>,
    ca: Option<String>,
    flags: CertificateFlags,
    expires_at: Option<DateTime<FixedOffset>>,
    #[serde(default)]
    domains: Vec<String>,
    environment: Option<CertificateEnvironment>,
}

#[derive(Deserialize, Debug)]
struct CertificateFlags {
    active: bool,
    legacy: bool,
}

#[derive(Deserialize, Debug)]
struct CertificateEnvironment {
    id: String,
    name: String,
}

#[derive(Deserialize, Debug, serde::Serialize, Clone)]
struct CertificatePayload {
    legacy: bool,
    label: String,
    certificate: String,
    private_key: String,
    ca_certificates: String,
}

#[derive(Deserialize, Debug)]
struct TaskAcceptedResponse {
    #[serde(rename = "_links")]
    links: TaskLinks,
}

#[derive(Deserialize, Debug)]
struct TaskLinks {
    notification: LinkHref,
}

#[derive(Deserialize, Debug)]
struct LinkHref {
    href: String,
}

#[derive(Deserialize, Debug)]
struct NotificationResponse {
    status: String,
    description: Option<String>,
}

#[derive(Deserialize, Debug)]
struct DefaultConfig {
    default_credentials: Option<Credentials>,
    sites: HashMap<String, SiteConfig>,
}

#[derive(Deserialize, Debug)]
struct SiteConfig {
    label: Option<String>,
    credentials: Option<Credentials>,
    environments: Vec<String>,
}

#[derive(Deserialize, Debug)]
struct Credentials {
    client_id: String,
    client_secret: String,
}

/// Entry point for the Certbot `renew_hook` binary.
///
/// Loads site mappings from `ACQUIA_CONFIG_PATH` (defaulting to `/etc/acquia-certbot/domains.json`),
/// reads the renewed PEM files from `RENEWED_LINEAGE`, authenticates against the Acquia Cloud API,
/// and deploys/activates the certificate across every configured environment UUID.
///
/// # Panics
///
/// Panics if the configuration file or PEM files cannot be read, no matching site or credentials
/// exist for the renewed lineage, or OAuth2 token acquisition fails.
fn main() {
    let dry_run = env::args().any(|arg| arg == "--dry-run");

    let config_path = env::var("ACQUIA_CONFIG_PATH")
        .unwrap_or_else(|_| "/etc/acquia-certbot/domains.json".to_string());

    let mut config = load_config(&config_path);

    let mut headers: HeaderMap = HeaderMap::new();
    headers.insert(ACCEPT, "application/hal+json".parse().unwrap());
    headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());

    // Build the http client
    let http_client = reqwest::blocking::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .default_headers(headers)
        .build()
        .expect("Client should build");

    let renewed_lineage =
        env::var("RENEWED_LINEAGE").expect("RENEWED_LINEAGE environment variable must be set");

    let lineage_path = Path::new(&renewed_lineage);

    let certificate =
        fs::read_to_string(lineage_path.join("cert.pem")).expect("Failed to Read Certificate.");

    let private_key =
        fs::read_to_string(lineage_path.join("privkey.pem")).expect("Failed to Read Private Key");

    let chain = fs::read_to_string(lineage_path.join("chain.pem")).expect("Failed to read Chain");

    // Build a Label for the cert.
    let cert_name = lineage_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("Certbot");

    let sites = config
        .sites
        .remove(cert_name)
        .unwrap_or_else(|| panic!("No entry found for '{cert_name}' in {config_path}"));

    let label_prefix = sites.label.as_deref().unwrap_or(cert_name);
    let label = format!("{label_prefix} - {}", Local::now().format("%Y%m%d"));

    if dry_run {
        println!(
            "Dry run for '{cert_name}' (label: '{label}') -> {:?}')",
            sites.environments
        );
        return;
    }

    const SSLCOM_ECC_ROOT_2022: &str = include_str!("../certs/sslcom-tls-ecc-root-2022.pem");
    let ca_certificates = if chain.contains(SSLCOM_ECC_ROOT_2022.trim()) {
        chain
    } else {
        format!("{}\n{}", chain.trim_end(), SSLCOM_ECC_ROOT_2022.trim())
    };

    // Create the payload Object.
    let payload = CertificatePayload {
        label,
        legacy: false,
        certificate,
        private_key,
        ca_certificates,
    };
    let oauth_credentials = sites
        .credentials
        .or(config.default_credentials)
        .unwrap_or_else(|| panic!("No credentials configured for '{cert_name}'in {config_path}"));

    let bearer_token = fetch_token(&http_client, &oauth_credentials)
        .unwrap_or_else(|e| panic!("Authentication failed for '{cert_name}': {e}"));

    // Start a loop over all uuids.
    let mut errors = Vec::new();
    for env_uuid in &sites.environments {
        println!("Deploying '{}' to environment {env_uuid}", payload.label);

        if let Err(err) = deploy_to_env(&http_client, &bearer_token, env_uuid, &payload) {
            errors.push((env_uuid.clone(), err));
        }
    }

    if !errors.is_empty() {
        eprintln!("Deployment completed with {} failure(s).", errors.len());
        process::exit(1);
    }
}

/// Polls an Acquia Cloud notification endpoint every 5 seconds until the asynchronous task finishes.
///
/// # Panics
///
/// Panics if the HTTP response body from the notification endpoint cannot be read or parsed as JSON.
///
/// # Errors
///
/// Returns an `Err` if:
/// - `timeout` elapses before the task reaches `"completed"` or `"failed"`.
/// - The HTTP request fails or returns a non-success status code.
/// - Acquia reports the task status as `"failed"`.
fn wait_for_task(
    http_client: &reqwest::blocking::Client,
    token: &str,
    notification_href: &str,
    timeout: Duration,
) -> Result<(), String> {
    let start = Instant::now();
    let poll_interval = Duration::from_secs(5);

    loop {
        if start.elapsed() > timeout {
            return Err(format!("Time out waiting for task: {notification_href}"));
        }

        let response = http_client
            .get(notification_href)
            .bearer_auth(token)
            .send()
            .map_err(|e| format!("Failed to poll notification: {e}"))?
            .error_for_status()
            .map_err(|e| format!("Notification endpoint returned error: {e}"))?;

        let notif: NotificationResponse =
            serde_json::from_str(&response.text().expect("Failed to process response body"))
                .expect("Failed to parse json");
        match notif.status.as_str() {
            "completed" => return Ok(()),
            "failed" => {
                return Err(format!(
                    "Acquia task failed: {}",
                    notif.description.unwrap_or_else(|| "unknown error".into())
                ));
            }
            _ => thread::sleep(poll_interval),
        }
    }
}

/// Uploads a certificate payload to a single Acquia Cloud environment and activates it.
///
/// Executes the full deployment lifecycle for `env_uuid`:
/// 1. `POST`s the certificate, private key, and chain to `/environments/{env_uuid}/ssl/certificates`.
/// 2. Waits for the upload notification task to complete.
/// 3. Queries existing certificates to locate the newly uploaded inactive, non-legacy certificate.
/// 4. `POST`s to `/actions/activate` and waits for the activation task to complete.
///
/// # Errors
///
/// Returns an `Err` if any API request fails, Acquia rejects the upload or activation payload,
/// a background notification task times out or fails, or the uploaded certificate cannot be located.
fn deploy_to_env(
    http_client: &reqwest::blocking::Client,
    token: &str,
    env_uuid: &str,
    payload: &CertificatePayload,
) -> Result<(), String> {
    const BASE_URL: &str = "https://cloud.acquia.com/api";
    let now = Utc::now();
    let json_body =
        serde_json::to_string(payload).map_err(|e| format!("Failed to serialize payload: {e}"))?;

    let upload_response = http_client
        .post(format!(
            "{BASE_URL}/environments/{}/ssl/certificates",
            env_uuid
        ))
        .bearer_auth(token)
        .body(json_body)
        .send()
        .map_err(|e| format!("Failed to send payload {e}"))?;

    let upload_response_status = upload_response.status();
    let upload_body = upload_response
        .text()
        .map_err(|e| format!("Failed to read upload response {e}"))?;

    if !upload_response_status.is_success() {
        return Err(format!(
            "Acquia rejected certificate upload ({upload_response_status}): {upload_body}"
        ));
    }

    let accepted_tasks: TaskAcceptedResponse = serde_json::from_str(&upload_body)
        .map_err(|e| format!("Failed to parse upload response {e}"))?;

    // Wait for the cert to fully upload.
    wait_for_task(
        http_client,
        token,
        &accepted_tasks.links.notification.href,
        Duration::from_secs(180),
    )?;

    // Get all the certificates for this environment to filter on the latest one.
    let certificates = http_client
        .get(format!(
            "{BASE_URL}/environments/{}/ssl/certificates",
            env_uuid
        ))
        .bearer_auth(token)
        .send()
        .map_err(|e| format!("Failed to fetch certificates: {e}"))?
        .error_for_status()
        .map_err(|e| format!("HTTP error fetching certificates: {e}"))?;

    // Get the body text out of the response object
    let certificates_body = certificates
        .text()
        .map_err(|e| format!("Failed to read certificates response body: {e}"))?;
    // Parse the data and create our Object to use.
    let certdata: AcquiaCollection<Certificate> = serde_json::from_str(&certificates_body)
        .map_err(|e| format!("Failed to parse certificates JSON: {e}"))?;

    // Find the Newest inactive non legacy cert.
    let newest_inactive = certdata
        .embedded
        .items
        .into_iter()
        .filter(|cert| {
            // Ensure the cert we want is not active.
            let is_inactive = !cert.flags.active;
            // Ensure the cert is not the legacy kind.
            let is_not_legacy = !cert.flags.legacy;
            // Ensure that the cert is not one that is already expired
            let is_unexpired = match cert.expires_at {
                Some(expires) => expires.with_timezone(&Utc) > now,
                None => false,
            };

            is_inactive && is_not_legacy && is_unexpired
        })
        .max_by_key(|cert| cert.id);

    // We should only send an activate on a cert id that matches our conditions.
    let Some(cert) = newest_inactive else {
        return Err(format!(
            "Uploaded certificate '{}' not found in inactive list for {env_uuid}",
            payload.label
        ));
    };
    // Activate the cert.
    let activate_res = http_client
        .post(format!(
            "{BASE_URL}/environments/{env_uuid}/ssl/certificates/{}/actions/activate",
            cert.id
        ))
        .bearer_auth(token)
        .send()
        .map_err(|e| format!("Request to activate cert {} failed: {e}", cert.id))?;

    let activate_status = activate_res.status();
    let activate_body = activate_res
        .text()
        .map_err(|e| format!("Failed to read activation response: {e}"))?;

    if !activate_status.is_success() {
        return Err(format!(
            "Acquia rejected cert {} activation ({activate_status}): {activate_body}",
            cert.id
        ));
    }

    let activate_task: TaskAcceptedResponse = serde_json::from_str(&activate_body)
        .map_err(|e| format!("Failed to parse activation response: {e}"))?;

    // Wait for activation task to finish so Certbot knows deployment actually completed
    wait_for_task(
        http_client,
        token,
        &activate_task.links.notification.href,
        Duration::from_secs(180),
    )?;

    Ok(())
}

/// Reads and deserializes the JSON configuration file from `config_path`.
///
/// # Panics
///
/// Panics if the file at `config_path` cannot be read or cannot be parsed into [`DefaultConfig`].
fn load_config(config_path: &str) -> DefaultConfig {
    let raw = fs::read_to_string(config_path)
        .unwrap_or_else(|e| panic!("Failed to read config at {config_path}: {e}"));

    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("Invalid JSON in {config_path}: {e}"))
}

/// Exchanges Acquia Cloud OAuth2 client credentials for a bearer access token.
///
/// # Errors
///
/// Returns an `Err` if the token endpoint URL is invalid or the OAuth2 client-credentials
/// token exchange request fails.
fn fetch_token(
    http_client: &reqwest::blocking::Client,
    credentials: &Credentials,
) -> Result<String, String> {
    // Acquia API Client ID
    let client_id = ClientId::new(credentials.client_id.clone());

    // Acquia API Client Secret
    let client_secret = ClientSecret::new(credentials.client_secret.clone());

    // Acquia Login API Endpoint
    let token_url = TokenUrl::new("https://accounts.acquia.com/api/auth/oauth/token".to_string())
        .map_err(|e| format!("Invalid token URL: {e}"))?;

    // Create a HTTP CLient
    let oauth_client = BasicClient::new(client_id)
        .set_client_secret(client_secret)
        .set_token_uri(token_url)
        .set_auth_type(AuthType::RequestBody);

    // Make the request to get the OAuth Token
    let token_response = oauth_client
        .exchange_client_credentials()
        .request(http_client)
        .map_err(|e| format!("Failed to fetch Oauth Bearer Token: {e}"))?;

    // Return the bearer token
    Ok(token_response.access_token().secret().to_string())
}
