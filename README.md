# Network Threat Scanner

A comprehensive automated network threat scanning system with Python backend and React frontend.

## Architecture

- **Backend (Python/Flask)**: Handles Nmap scans, anomaly detection, PGP-encrypted email alerts, scheduling, and admin dashboard.
- **Frontend (React + Vite)**: User interface for monitoring scans and triggering manual scans.

## Features

- Configurable Nmap scans on multiple targets
- Real-time anomaly detection (new ports, changed services, critical port alerts)
- PGP-encrypted email alerts to multiple recipients
- Scheduled and manual scanning
- Admin dashboard for configuration and monitoring
- Beautiful React UI with Tailwind CSS

## Setup

1. **Backend**:
   - Navigate to `backend/` directory.
   - Install dependencies: `pip install -r requirements.txt`
   - Configure `.env` with SMTP, GPG, and dashboard settings.
   - Run: `python scanner.py`

2. **Frontend**:
   - Navigate to `frontend/` directory.
   - Install dependencies: `npm install`
   - Run: `npm run dev`

## Access

- **Admin Dashboard**: http://localhost:5000 (requires DASHBOARD_TOKEN)
- **User Interface**: http://localhost:5173

## Security Notes

- Configure PGP keys and SMTP credentials securely.
- Use environment variables for sensitive data.
- Run scans on authorized networks only.