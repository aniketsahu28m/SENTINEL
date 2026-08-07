# Network Threat Scanner Backend

This is the backend for a comprehensive network threat scanning system using Python and Flask.

## Features

- Automated Nmap scanning with configurable arguments
- Anomaly detection comparing scans over time
- PGP-encrypted email alerts for detected anomalies
- Flask-based admin dashboard for configuration
- REST API for external integrations

## Setup

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Configure environment variables in `.env` file:
   - SMTP settings for email alerts
   - GPG home directory
   - (Optional) `DEFAULT_ADMIN_PASSWORD` to seed the initial admin user
   - (Optional) `ALLOWED_ORIGINS` comma-separated list for CORS

3. Configure scan settings in `data/config.json`:
   - List of targets to scan
   - Scan arguments
   - Scan interval
   - Recipients for alerts
   - Critical ports for high-priority alerts

4. Set up PGP keys:
   - Generate or import keys for encryption
   - Ensure recipients have public keys available

5. Run the scanner:
   ```
   python scanner.py
   ```

The Flask app will start on http://localhost:5000 with admin dashboard.

## Authentication

- User identities are stored in `data/users.json` with bcrypt-hashed passwords.
- The server automatically bootstraps an `admin` user on first run. Override the default password by setting `DEFAULT_ADMIN_PASSWORD` before the initial start.
- Authenticate by sending `POST /login` with JSON credentials:
  ```json
  {
    "username": "admin",
    "password": "<your-password>"
  }
  ```
- Successful authentication returns a bearer token and issues a secure cookie. Include the token in subsequent requests using the `Authorization: Bearer <token>` header.
- Sessions expire automatically (default 60 minutes). Log out explicitly with `POST /logout`.

## Report Encryption

- Use `GET /reports` to list plaintext and encrypted scan/anomaly reports.
- Encrypt a report with `POST /reports/encrypt` providing `report_type` (`scan` or `anomaly`) and `filename`. The encrypted artifact is stored under `data/encrypted_reports/`.
- Decrypt a stored artifact with `POST /reports/decrypt` supplying the `encrypted_file` name returned earlier.
- AES-GCM keys are generated automatically and stored in `data/keys.json`. Protect this file to safeguard encrypted content.

## API Endpoints

- GET /status: Get system status and last scan summary.
- POST /scan: Trigger a manual scan.
- GET /logs: Get list of past scans.

## Dashboard

Access the admin dashboard at http://localhost:5000 with the DASHBOARD_TOKEN for authentication.

## File Structure

- `data/config.json`: Configuration settings
- `data/scans/`: JSON files of scan results
- `data/anomalies/`: JSON files of detected anomalies