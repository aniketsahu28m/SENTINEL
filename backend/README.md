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
   - Dashboard authentication token

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