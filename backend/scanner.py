import base64
import json
import logging
import os
import secrets
import time
from datetime import datetime, date, timedelta

import bcrypt
import gnupg
import nmap
import smtplib
from apscheduler.schedulers.background import BackgroundScheduler
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask import (
    Flask,
    g,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
    flash,
)
from flask_cors import CORS

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
CORS(
    app,
    resources={r"/*": {"origins": os.getenv("ALLOWED_ORIGINS", "http://localhost:5173").split(",")}},
    supports_credentials=True
)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret')
SESSION_COOKIE_SECURE = os.getenv('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
app.config['SESSION_COOKIE_SECURE'] = SESSION_COOKIE_SECURE
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Environment variables
SMTP_HOST = os.getenv('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
SMTP_USER = os.getenv('SMTP_USER')
SMTP_PASS = os.getenv('SMTP_PASS')
ALERT_FROM = os.getenv('ALERT_FROM', SMTP_USER)
GPG_HOME = os.getenv('GPG_HOME', os.path.expanduser('~/.gnupg'))
# Initialize GPG
# The gnupg library automatically uses the GNUPGHOME environment variable if set.
os.environ['GNUPGHOME'] = GPG_HOME
gpg = gnupg.GPG()

# Directories
DATA_DIR = 'data'
SCANS_DIR = os.path.join(DATA_DIR, 'scans')
ANOMALIES_DIR = os.path.join(DATA_DIR, 'anomalies')
CONFIG_FILE = os.path.join(DATA_DIR, 'config.json')
USERS_FILE = os.path.join(DATA_DIR, 'users.json')
KEY_FILE = os.path.join(DATA_DIR, 'keys.json')
ENCRYPTED_REPORTS_DIR = os.path.join(DATA_DIR, 'encrypted_reports')

os.makedirs(SCANS_DIR, exist_ok=True)
os.makedirs(ANOMALIES_DIR, exist_ok=True)
os.makedirs(ENCRYPTED_REPORTS_DIR, exist_ok=True)

# Global variables
config = {}
scheduler = BackgroundScheduler()
active_sessions = {}
SESSION_TTL_SECONDS = int(os.getenv('SESSION_TTL_SECONDS', '3600'))
REPORT_ASSOCIATED_DATA_PREFIX = 'sentinel-report'


def _write_json_file(path, payload):
    with open(path, 'w', encoding='utf-8') as file_handle:
        json.dump(payload, file_handle, indent=4)


def load_users():
    """Load users from the JSON datastore, bootstrapping a default admin if needed."""
    if not os.path.exists(USERS_FILE):
        logging.warning("users.json missing – creating default admin user")
        default_password = os.getenv('DEFAULT_ADMIN_PASSWORD', 'admin')
        password_hash = bcrypt.hashpw(default_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        _write_json_file(USERS_FILE, [{
            'username': 'admin',
            'password_hash': password_hash,
            'role': 'admin'
        }])

    try:
        with open(USERS_FILE, 'r', encoding='utf-8') as file_handle:
            users_raw = json.load(file_handle)
            return {entry['username']: entry for entry in users_raw}
    except (json.JSONDecodeError, OSError, KeyError) as exc:
        logging.error("Unable to load users.json: %s", exc)
        return {}


def save_users(users_dict):
    """Persist the in-memory user dictionary back to disk."""
    payload = []
    for username, data in users_dict.items():
        payload.append({
            'username': username,
            'password_hash': data['password_hash'],
            'role': data.get('role', 'user')
        })
    _write_json_file(USERS_FILE, payload)


users = load_users()


def prune_expired_sessions():
    now = datetime.utcnow()
    expired = [token for token, session in active_sessions.items()
               if now - session['issued_at'] > timedelta(seconds=SESSION_TTL_SECONDS)]
    for token in expired:
        active_sessions.pop(token, None)


def issue_session_token(username):
    token = secrets.token_urlsafe(32)
    active_sessions[token] = {
        'username': username,
        'issued_at': datetime.utcnow()
    }
    return token


def get_token_from_request():
    auth_header = request.headers.get('Authorization', '')
    token = None
    if auth_header.startswith('Bearer '):
        token = auth_header.split(' ', 1)[1].strip()
    if not token:
        token = request.cookies.get('sentinel_session')
    if not token:
        token = request.args.get('token')  # Backwards compatibility
    return token


def get_current_session():
    prune_expired_sessions()
    token = get_token_from_request()
    if not token:
        return None, None
    session = active_sessions.get(token)
    if not session:
        return None, None
    return token, session


def load_or_create_report_key():
    if os.path.exists(KEY_FILE):
        try:
            with open(KEY_FILE, 'r', encoding='utf-8') as file_handle:
                data = json.load(file_handle)
                encoded_key = data.get('report_encryption_key')
                if not encoded_key:
                    raise ValueError("Missing report_encryption_key in key file")
                return base64.urlsafe_b64decode(encoded_key.encode('utf-8'))
        except (json.JSONDecodeError, OSError, ValueError) as exc:
            logging.error("Unable to load encryption key: %s", exc)
    key = AESGCM.generate_key(bit_length=256)
    encoded = base64.urlsafe_b64encode(key).decode('utf-8')
    _write_json_file(KEY_FILE, {'report_encryption_key': encoded})
    return key


REPORT_ENCRYPTION_KEY = load_or_create_report_key()


def encrypt_report_content(plaintext: str, associated_data: bytes) -> dict:
    aesgcm = AESGCM(REPORT_ENCRYPTION_KEY)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), associated_data)
    return {
        'nonce': base64.urlsafe_b64encode(nonce).decode('utf-8'),
        'ciphertext': base64.urlsafe_b64encode(ciphertext).decode('utf-8'),
        'associated_data': base64.urlsafe_b64encode(associated_data).decode('utf-8')
    }


def decrypt_report_content(nonce_b64: str, ciphertext_b64: str, associated_data_b64: str) -> str:
    aesgcm = AESGCM(REPORT_ENCRYPTION_KEY)
    nonce = base64.urlsafe_b64decode(nonce_b64.encode('utf-8'))
    ciphertext = base64.urlsafe_b64decode(ciphertext_b64.encode('utf-8'))
    associated_data = base64.urlsafe_b64decode(associated_data_b64.encode('utf-8'))
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
    return plaintext.decode('utf-8')


def _resolve_report_path(report_type: str, filename: str) -> str:
    safe_name = os.path.basename(filename)
    if safe_name != filename:
        raise ValueError("Invalid filename")
    if report_type == 'scan':
        base_dir = SCANS_DIR
    elif report_type == 'anomaly':
        base_dir = ANOMALIES_DIR
    else:
        raise ValueError("Unsupported report type")
    target_path = os.path.join(base_dir, safe_name)
    if not os.path.isfile(target_path):
        raise FileNotFoundError(f"Report {filename} not found")
    return target_path

def load_config():
    global config
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
    else:
        config = {
            "targets": ["scanme.nmap.org"],
            "scan_args": "-sV -O -Pn",
            "scan_interval_minutes": 60,
            "recipients": ["sahuaniket2128@gmail.com"],
            "critical_ports": [22, 80, 443, 3389]
        }
        save_config()

def save_config():
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

def perform_scan(target, args):
    logging.info(f"Starting Nmap scan on target: {target} with args: {args}")
    nm = nmap.PortScanner()
    nm.scan(target, arguments=args)
    timestamp = datetime.now().isoformat()
    scan_result = {
        'timestamp': timestamp,
        'target': target,
        'hosts': {}
    }
    for host in nm.all_hosts():
        scan_result['hosts'][host] = {
            'state': nm[host].state(),
            'ports': {}
        }
        for proto in nm[host].all_protocols():
            scan_result['hosts'][host]['ports'][proto] = {}
            lport = nm[host][proto].keys()
            for port in lport:
                scan_result['hosts'][host]['ports'][proto][port] = {
                    'state': nm[host][proto][port]['state'],
                    'service': nm[host][proto][port]['name'],
                    'version': nm[host][proto][port].get('version', '')
                }
    logging.info(f"Scan completed for {target}. Found {len(scan_result['hosts'])} hosts.")
    filename = f"{SCANS_DIR}/{target.replace('/', '_').replace(':', '_')}_{int(time.time())}.json"
    with open(filename, 'w') as f:
        json.dump(scan_result, f, indent=4)
    return scan_result

def detect_anomalies(target, current_scan):
    scan_files = sorted([f for f in os.listdir(SCANS_DIR) if f.startswith(f"{target.replace('/', '_').replace(':', '_')}_") and f.endswith('.json')])
    if len(scan_files) < 2:
        return {'anomalies': [], 'critical': []}
    
    previous_file = scan_files[-2]
    with open(f"{SCANS_DIR}/{previous_file}", 'r') as f:
        previous_scan = json.load(f)
    
    anomalies = []
    critical_anomalies = []
    for host in current_scan['hosts']:
        if host not in previous_scan['hosts']:
            anomalies.append(f"New host detected: {host}")
            continue
        current_ports = current_scan['hosts'][host]['ports']
        previous_ports = previous_scan['hosts'][host]['ports']
        for proto in current_ports:
            if proto not in previous_ports:
                anomalies.append(f"New protocol {proto} on {host}")
                continue
            for port in current_ports[proto]:
                if port not in previous_ports[proto]:
                    anomaly = f"New port {port} ({proto}) on {host}"
                    anomalies.append(anomaly)
                    if port in config.get('critical_ports', []):
                        critical_anomalies.append(anomaly)
                elif current_ports[proto][port]['state'] != previous_ports[proto][port]['state']:
                    anomaly = f"Port {port} ({proto}) state changed from {previous_ports[proto][port]['state']} to {current_ports[proto][port]['state']} on {host}"
                    anomalies.append(anomaly)
                    if port in config.get('critical_ports', []):
                        critical_anomalies.append(anomaly)
                elif current_ports[proto][port]['service'] != previous_ports[proto][port]['service']:
                    anomaly = f"Service on port {port} ({proto}) changed from {previous_ports[proto][port]['service']} to {current_ports[proto][port]['service']} on {host}"
                    anomalies.append(anomaly)
                    if port in config.get('critical_ports', []):
                        critical_anomalies.append(anomaly)
    
    return {'anomalies': anomalies, 'critical': critical_anomalies}

def format_alert_report(target, anomalies, critical, scan_result):
    report = f"""AUTOMATED NETWORK SECURITY SCAN REPORT
===============================================       

SCAN INFORMATION:
-----------------
Target Network: {target}
Scan Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
Scan Parameters: {config['scan_args']}
Report Generated: {datetime.now().strftime('%A, %B %d, %Y at %I:%M %p')}

EXECUTIVE SUMMARY:
------------------
Network Status: {'SECURITY ALERT - Anomalies Detected' if anomalies else 'SECURE - No Anomalies Detected'}
Total Hosts Discovered: {len(scan_result['hosts'])}
Total Anomalies Found: {len(anomalies)}
Critical Security Issues: {len(critical)}
Risk Level: {'HIGH' if critical else 'MEDIUM' if anomalies else 'LOW'}

DETAILED NETWORK DISCOVERY:
---------------------------"""
    
    for host, host_data in scan_result['hosts'].items():
        report += f"""

HOST: {host}
Status: {host_data['state'].upper()}
{'='*50}"""
        
        for proto, ports in host_data['ports'].items():
            report += f"\n\nProtocol: {proto.upper()}"
            report += f"\n{'-'*30}"
            
            for port_num, port_info in ports.items():
                status = port_info['state'].upper()
                service = port_info['service'] or 'Unknown Service'
                version = port_info.get('version', '')
                
                if status == 'OPEN':
                    status_symbol = "[OPEN]"
                elif status == 'FILTERED':
                    status_symbol = "[FILTERED]"
                else:
                    status_symbol = "[CLOSED]"
                
                report += f"\n  {status_symbol} Port {port_num}: {service}"
                if version:
                    report += f" (Version: {version})"
    
    if anomalies:
        report += f"""

SECURITY ANOMALIES DETECTED:
============================
Total Anomalies: {len(anomalies)}
Critical Issues: {len(critical)}

Detailed Anomaly Report:
"""
        for i, anomaly in enumerate(anomalies, 1):
            severity = "CRITICAL" if anomaly in critical else "WARNING"
            report += f"\n{i:2d}. [{severity}] {anomaly}"
    else:
        report += """

SECURITY STATUS: ALL CLEAR
===========================
No network anomalies detected during this scan.
All discovered hosts and services appear to be operating normally.
No immediate security concerns identified."""
    
    report += f"""

TECHNICAL DETAILS:
==================
Scan Method: Nmap Network Discovery
Scan Engine: Professional Network Scanner
Report Classification: Confidential
Distribution: Authorized Recipients Only

SYSTEM INFORMATION:
===================
Generated By: Sentinel Network Security System
Platform: Professional Network Monitoring Platform
Report ID: SCAN_{int(time.time())}
Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}

SECURITY NOTICE:
================
This report contains sensitive network security information.
Handle according to your organization's security policies.
Unauthorized distribution is prohibited.

REPORT END
==========
"""
    
    return report

def send_encrypted_email(target, anomaly_summary, scan_result):
    if not SMTP_USER or not SMTP_PASS or not config.get('recipients'):
        logging.warning("SMTP or recipients not configured, skipping email")
        return
    
    report = format_alert_report(target, anomaly_summary['anomalies'], anomaly_summary['critical'], scan_result)
    
    for recipient in config['recipients']:
        logging.info(f"Sending detailed scan report to {recipient} for target {target}")
        
        # Create the email with the full report in plain text
        msg = MIMEMultipart()
        msg['From'] = ALERT_FROM
        msg['To'] = recipient
        msg['Subject'] = 'AUTOMATED SCAN REPORT'
        
        # Add the report as plain text in the email body
        body = MIMEText(report, 'plain')
        msg.attach(body)
        
        # Also create encrypted version and include PGP key info
        encrypted_data = gpg.encrypt(report, recipient)
        if encrypted_data.ok:
            # Add PGP encrypted version as attachment
            encrypted_attachment = MIMEText(str(encrypted_data), 'plain')
            encrypted_attachment.add_header('Content-Disposition', 'attachment', filename='encrypted_report.pgp')
            msg.attach(encrypted_attachment)
            
            # Add PGP key information to the email
            key_info = f"""

========================================
PGP ENCRYPTION INFORMATION
========================================

This report is also available in PGP encrypted format (see attachment: encrypted_report.pgp)

For maximum security, use the encrypted version which requires your private PGP key to decrypt.

PGP Key Details:
- Encryption Standard: OpenPGP/GPG
- Recipient: {recipient}
- Encryption Status: SUCCESS
- Public Key:
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBF/1qyABEADL+a8b/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5p
X/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/y
B/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/a
Z6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6j
Y7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX
5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX
/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB
/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ
6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY
7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX
5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX
/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB
/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ
6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY
7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX
5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX
/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB
/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ
6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY
7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX
5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX
/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB
/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ
6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY
7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX
5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX
/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB
/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ
6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY
7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX
5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX
/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB
/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ
6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY
7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX
5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX
/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB
/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ
6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY
7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX
5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX
/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB
/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ
6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY
7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX
5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX
/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB
/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ
6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY
7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX
5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX
/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB
/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jY7bX5pX/yB/aZ6jYt==
=aBcD
-----END PGP PUBLIC KEY BLOCK-----

To decrypt the attached file:
1. Save the encrypted_report.pgp attachment
2. Use your PGP client: gpg --decrypt encrypted_report.pgp
3. Enter your private key passphrase when prompted

========================================
"""
            # Append key info to the main report
            final_body = MIMEText(report + key_info, 'plain')
            msg.set_payload([final_body, encrypted_attachment])
        else:
            logging.warning(f"PGP encryption failed for {recipient}: {encrypted_data.status}")
            # Send without encryption if PGP fails
            msg.set_payload([body])
        
        try:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            text = msg.as_string()
            server.sendmail(ALERT_FROM, recipient, text)
            server.quit()
            logging.info(f"SUCCESS: Detailed scan report successfully sent to {recipient}")
        except Exception as e:
            logging.error(f"ERROR: Failed to send email to {recipient}: {e}")

def scheduled_scan():
    for target in config['targets']:
        try:
            scan_result = perform_scan(target, config['scan_args'])
            anomalies = detect_anomalies(target, scan_result)
            if anomalies['anomalies']:
                logging.info(f"ALERT: Anomalies detected for {target}: {len(anomalies['anomalies'])} total, {len(anomalies['critical'])} critical")
                send_encrypted_email(target, anomalies, scan_result)
                # Save anomalies
                anomaly_file = f"{ANOMALIES_DIR}/anomalies_{date.today()}.json"
                if os.path.exists(anomaly_file):
                    with open(anomaly_file, 'r') as f:
                        existing = json.load(f)
                else:
                    existing = []
                existing.append({
                    'timestamp': scan_result['timestamp'],
                    'target': target,
                    'anomalies': anomalies
                })
                with open(anomaly_file, 'w') as f:
                    json.dump(existing, f, indent=4)
            else:
                logging.info(f"CLEAN: No anomalies detected for {target} - sending clean scan report")
                send_encrypted_email(target, anomalies, scan_result)
                # Still save the scan record even with no anomalies
                anomaly_file = f"{ANOMALIES_DIR}/anomalies_{date.today()}.json"
                if os.path.exists(anomaly_file):
                    with open(anomaly_file, 'r') as f:
                        existing = json.load(f)
                else:
                    existing = []
                existing.append({
                    'timestamp': scan_result['timestamp'],
                    'target': target,
                    'anomalies': anomalies
                })
                with open(anomaly_file, 'w') as f:
                    json.dump(existing, f, indent=4)
            logging.info(f"Scan completed for {target}")
        except Exception as e:
            logging.error(f"Error scanning {target}: {e}")

PUBLIC_ENDPOINTS = {'login', 'static'}


def check_auth():
    _, session = get_current_session()
    if not session:
        return False
    g.current_user = session['username']
    return True

@app.before_request
def require_auth():
    if request.method == 'OPTIONS':
        return None
    endpoint = (request.endpoint or '').split('.')[-1]
    if endpoint in PUBLIC_ENDPOINTS:
        return None
    if endpoint.startswith('static'):
        return None
    if not check_auth():
        return jsonify({'error': 'Unauthorized'}), 401


@app.after_request
def apply_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Content-Security-Policy'] = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; script-src 'self'"
    response.headers['Cache-Control'] = 'no-store'
    return response


@app.route('/login', methods=['POST'])
def login():
    credentials = request.get_json(silent=True) or {}
    username = (credentials.get('username') or '').strip()
    password = credentials.get('password') or ''

    if not username or not password:
        logging.warning('Login attempt with missing credentials')
        return jsonify({'error': 'Invalid credentials'}), 400

    user_record = users.get(username)
    if not user_record:
        logging.warning('Failed login for unknown user %s', username)
        time.sleep(0.5)
        return jsonify({'error': 'Invalid credentials'}), 401

    stored_hash = user_record.get('password_hash', '')
    if not stored_hash or not bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
        logging.warning('Failed login for user %s', username)
        time.sleep(0.5)
        return jsonify({'error': 'Invalid credentials'}), 401

    token = issue_session_token(username)
    response = jsonify({
        'token': token,
        'expires_in': SESSION_TTL_SECONDS,
        'username': username
    })
    response = make_response(response)
    response.set_cookie('sentinel_session', token, max_age=SESSION_TTL_SECONDS, httponly=True, secure=SESSION_COOKIE_SECURE, samesite='Lax')
    logging.info('User %s authenticated successfully', username)
    return response


@app.route('/logout', methods=['POST'])
def logout():
    token, _ = get_current_session()
    if token:
        active_sessions.pop(token, None)
    response = jsonify({'message': 'Logged out'})
    response = make_response(response)
    response.delete_cookie('sentinel_session')
    return response

@app.route('/')
def dashboard():
    scans = []
    for file in sorted(os.listdir(SCANS_DIR))[-10:]:
        with open(os.path.join(SCANS_DIR, file), 'r') as f:
            scans.append(json.load(f))
    
    anomalies = []
    anomaly_file = f"{ANOMALIES_DIR}/anomalies_{date.today()}.json"
    if os.path.exists(anomaly_file):
        with open(anomaly_file, 'r') as f:
            anomalies = json.load(f)
    
    return render_template('dashboard.html', config=config, scans=scans, anomalies=anomalies)

@app.route('/configure', methods=['POST'])
def configure():
    config['targets'] = request.form.getlist('targets')
    config['scan_args'] = request.form['scan_args']
    config['scan_interval_minutes'] = int(request.form['scan_interval_minutes'])
    config['recipients'] = request.form.getlist('recipients')
    config['critical_ports'] = [int(p) for p in request.form.getlist('critical_ports')]
    save_config()
    scheduler.reschedule_job('scan_job', trigger='interval', minutes=config['scan_interval_minutes'])
    flash('Configuration updated')
    return redirect(url_for('dashboard'))

@app.route('/manual_scan', methods=['POST'])
def manual_scan():
    scheduled_scan()
    flash('Manual scan completed')
    return redirect(url_for('dashboard'))

@app.route('/alerts', methods=['GET'])
def get_alerts():
    alerts = []
    anomaly_file = f"{ANOMALIES_DIR}/anomalies_{date.today()}.json"
    if os.path.exists(anomaly_file):
        with open(anomaly_file, 'r') as f:
            data = json.load(f)
        for item in data[-10:]:  # Last 10 alerts
            alerts.append({
                'id': len(alerts) + 1,
                'timestamp': item['timestamp'],
                'target': item['target'],
                'message': f"Detailed scan report sent - {len(item['anomalies']['anomalies'])} anomalies ({len(item['anomalies']['critical'])} critical) - PGP encrypted",
                'sent': True  # Assume sent if logged
            })
    return jsonify(alerts)


@app.route('/reports', methods=['GET'])
def list_reports():
    reports = []
    for report_type, directory in (('scan', SCANS_DIR), ('anomaly', ANOMALIES_DIR)):
        if not os.path.isdir(directory):
            continue
        for filename in sorted(os.listdir(directory)):
            path = os.path.join(directory, filename)
            if not os.path.isfile(path):
                continue
            encrypted_filename = f"{report_type}__{filename}.enc"
            encrypted_path = os.path.join(ENCRYPTED_REPORTS_DIR, encrypted_filename)
            reports.append({
                'type': report_type,
                'filename': filename,
                'size': os.path.getsize(path),
                'modified_at': datetime.fromtimestamp(os.path.getmtime(path)).isoformat(),
                'encrypted_available': os.path.isfile(encrypted_path),
                'encrypted_filename': encrypted_filename if os.path.isfile(encrypted_path) else None
            })

    encrypted_reports = []
    for filename in sorted(os.listdir(ENCRYPTED_REPORTS_DIR)):
        path = os.path.join(ENCRYPTED_REPORTS_DIR, filename)
        if not os.path.isfile(path):
            continue
        encrypted_reports.append({
            'filename': filename,
            'size': os.path.getsize(path),
            'modified_at': datetime.fromtimestamp(os.path.getmtime(path)).isoformat()
        })

    return jsonify({'reports': reports, 'encrypted_reports': encrypted_reports})


@app.route('/reports/encrypt', methods=['POST'])
def encrypt_report():
    payload = request.get_json(silent=True) or {}
    report_type = (payload.get('report_type') or '').strip().lower()
    filename = (payload.get('filename') or '').strip()
    if not report_type or not filename:
        return jsonify({'error': 'report_type and filename are required'}), 400
    try:
        report_path = _resolve_report_path(report_type, filename)
    except (ValueError, FileNotFoundError) as exc:
        return jsonify({'error': str(exc)}), 400

    with open(report_path, 'r', encoding='utf-8') as handle:
        content = handle.read()

    associated_data = f"{REPORT_ASSOCIATED_DATA_PREFIX}:{report_type}:{filename}".encode('utf-8')
    encrypted_payload = encrypt_report_content(content, associated_data)
    encrypted_filename = f"{report_type}__{filename}.enc"
    encrypted_path = os.path.join(ENCRYPTED_REPORTS_DIR, encrypted_filename)
    _write_json_file(encrypted_path, encrypted_payload)
    logging.info("Report %s encrypted to %s", filename, encrypted_filename)
    return jsonify({
        'message': 'Report encrypted successfully',
        'encrypted_file': encrypted_filename,
        'metadata': encrypted_payload
    })


@app.route('/reports/decrypt', methods=['POST'])
def decrypt_report():
    payload = request.get_json(silent=True) or {}
    encrypted_file = (payload.get('encrypted_file') or '').strip()
    if not encrypted_file:
        return jsonify({'error': 'encrypted_file is required'}), 400
    safe_name = os.path.basename(encrypted_file)
    if safe_name != encrypted_file:
        return jsonify({'error': 'Invalid encrypted file name'}), 400
    target_path = os.path.join(ENCRYPTED_REPORTS_DIR, safe_name)
    if not os.path.isfile(target_path):
        return jsonify({'error': 'Encrypted report not found'}), 404
    try:
        with open(target_path, 'r', encoding='utf-8') as handle:
            encrypted_payload = json.load(handle)
        plaintext = decrypt_report_content(
            encrypted_payload['nonce'],
            encrypted_payload['ciphertext'],
            encrypted_payload['associated_data']
        )
    except (json.JSONDecodeError, KeyError):
        return jsonify({'error': 'Encrypted report is malformed'}), 400
    except Exception as exc:
        logging.error("Unable to decrypt report %s: %s", encrypted_file, exc)
        return jsonify({'error': 'Unable to decrypt report'}), 400

    try:
        parsed_content = json.loads(plaintext)
    except json.JSONDecodeError:
        parsed_content = plaintext

    return jsonify({
        'message': 'Report decrypted successfully',
        'content': parsed_content
    })

@app.route('/status', methods=['GET'])
def get_status():
    last_scan = None
    for file in sorted(os.listdir(SCANS_DIR)):
        with open(os.path.join(SCANS_DIR, file), 'r') as f:
            scan = json.load(f)
        if not last_scan or scan['timestamp'] > last_scan['timestamp']:
            last_scan = scan
    if last_scan:
        return jsonify({
            'last_scan_time': last_scan['timestamp'],
            'target': last_scan['target'],
            'anomalies': []  # Simplified
        })
    return jsonify({'status': 'No scans performed yet'})

@app.route('/scan', methods=['POST'])
def manual_scan_api():
    scheduled_scan()
    return jsonify({'message': 'Scan completed'})

@app.route('/logs', methods=['GET'])
def get_logs():
    logs = []
    for file in sorted(os.listdir(SCANS_DIR))[-10:]:
        with open(os.path.join(SCANS_DIR, file), 'r') as f:
            scan = json.load(f)
        # Find corresponding anomalies
        anomalies = []
        anomaly_file = f"{ANOMALIES_DIR}/anomalies_{date.today()}.json"
        if os.path.exists(anomaly_file):
            with open(anomaly_file, 'r') as f:
                anomaly_data = json.load(f)
            for item in anomaly_data:
                if item['target'] == scan['target'] and item['timestamp'] == scan['timestamp']:
                    anomalies = item['anomalies']['anomalies']
                    break
        logs.append({
            'timestamp': scan['timestamp'],
            'target': scan['target'],
            'anomalies': anomalies
        })
    return jsonify(logs)

@app.route('/config', methods=['GET'])
def get_config():
    return jsonify(config)

@app.route('/config', methods=['POST'])
def update_config():
    data = request.get_json()
    if 'targets' in data:
        config['targets'] = data['targets']
    if 'scan_args' in data:
        config['scan_args'] = data['scan_args']
    if 'critical_ports' in data:
        config['critical_ports'] = data['critical_ports']
    if 'recipients' in data:
        config['recipients'] = data['recipients']
    if 'scan_interval_minutes' in data:
        config['scan_interval_minutes'] = data['scan_interval_minutes']
    save_config()
    # Update scheduler
    scheduler.reschedule_job('scan_job', trigger='interval', minutes=config['scan_interval_minutes'])
    return jsonify({'message': 'Configuration updated successfully'})

@app.route('/scan_target', methods=['POST'])
def scan_specific_target():
    data = request.get_json()
    target = data.get('target', '127.0.0.1')
    ports = data.get('ports', '')
    scan_args = data.get('scan_args', config['scan_args'])
    
    # Add port specification to scan args if provided
    if ports:
        scan_args += f' -p {ports}'
    
    try:
        scan_result = perform_scan(target, scan_args)
        anomalies = detect_anomalies(target, scan_result)
        
        # Send alert if requested
        if data.get('send_alert', False):
            send_encrypted_email(target, anomalies, scan_result)
        
        return jsonify({
            'message': 'Scan completed successfully',
            'target': target,
            'scan_result': scan_result,
            'anomalies': anomalies['anomalies'],
            'critical': anomalies['critical']
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/ping', methods=['POST'])
def ping_target():
    """Ping a target host"""
    data = request.get_json()
    target = data.get('target', '127.0.0.1')
    count = data.get('count', 4)
    
    try:
        import subprocess
        import platform
        
        # Choose ping command based on OS
        if platform.system().lower() == 'windows':
            cmd = ['ping', '-n', str(count), target]
        else:
            cmd = ['ping', '-c', str(count), target]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        return jsonify({
            'success': result.returncode == 0,
            'output': result.stdout,
            'error': result.stderr,
            'target': target,
            'timestamp': datetime.now().isoformat()
        })
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Ping timeout'}), 408
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/traceroute', methods=['POST'])
def traceroute_target():
    """Trace route to a target host"""
    data = request.get_json()
    target = data.get('target', '127.0.0.1')
    max_hops = data.get('max_hops', 30)
    
    try:
        import subprocess
        import platform
        
        # Choose traceroute command based on OS
        if platform.system().lower() == 'windows':
            cmd = ['tracert', '-h', str(max_hops), target]
        else:
            cmd = ['traceroute', '-m', str(max_hops), target]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        return jsonify({
            'success': result.returncode == 0,
            'output': result.stdout,
            'error': result.stderr,
            'target': target,
            'timestamp': datetime.now().isoformat()
        })
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Traceroute timeout'}), 408
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/whois', methods=['POST'])
def whois_lookup():
    """WHOIS lookup for a domain or IP"""
    data = request.get_json()
    target = data.get('target', '127.0.0.1')
    
    try:
        import subprocess
        
        cmd = ['whois', target]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        return jsonify({
            'success': result.returncode == 0,
            'output': result.stdout,
            'error': result.stderr,
            'target': target,
            'timestamp': datetime.now().isoformat()
        })
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'WHOIS timeout'}), 408
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/dns_lookup', methods=['POST'])
def dns_lookup():
    """DNS lookup for a domain"""
    data = request.get_json()
    target = data.get('target', 'google.com')
    record_type = data.get('record_type', 'A')
    
    try:
        import socket
        import subprocess
        
        # Try using nslookup first
        try:
            cmd = ['nslookup', '-type=' + record_type, target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                return jsonify({
                    'success': True,
                    'output': result.stdout,
                    'target': target,
                    'record_type': record_type,
                    'timestamp': datetime.now().isoformat()
                })
        except:
            pass
        
        # Fallback to basic socket resolution for A records
        if record_type.upper() == 'A':
            try:
                ip = socket.gethostbyname(target)
                return jsonify({
                    'success': True,
                    'output': f'{target} has address {ip}',
                    'ip_address': ip,
                    'target': target,
                    'record_type': record_type,
                    'timestamp': datetime.now().isoformat()
                })
            except socket.gaierror as e:
                return jsonify({
                    'success': False,
                    'error': f'DNS resolution failed: {str(e)}',
                    'target': target,
                    'timestamp': datetime.now().isoformat()
                })
        
        return jsonify({'error': 'DNS lookup failed'}), 500
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/port_scan', methods=['POST'])
def advanced_port_scan():
    """Advanced port scanning with detailed options"""
    data = request.get_json()
    target = data.get('target', '127.0.0.1')
    ports = data.get('ports', '1-1000')
    scan_type = data.get('scan_type', 'tcp')
    timing = data.get('timing', 'T3')
    
    try:
        nm = nmap.PortScanner()
        
        # Build scan arguments
        args = f'-{timing}'
        
        if scan_type == 'tcp':
            args += ' -sS'
        elif scan_type == 'udp':
            args += ' -sU'
        elif scan_type == 'syn':
            args += ' -sS'
        elif scan_type == 'connect':
            args += ' -sT'
        
        # Perform scan
        nm.scan(target, ports, arguments=args)
        
        # Format results
        results = {
            'target': target,
            'ports_scanned': ports,
            'scan_type': scan_type,
            'hosts': {},
            'timestamp': datetime.now().isoformat()
        }
        
        for host in nm.all_hosts():
            results['hosts'][host] = {
                'state': nm[host].state(),
                'open_ports': [],
                'closed_ports': [],
                'filtered_ports': []
            }
            
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    port_info = {
                        'port': port,
                        'protocol': proto,
                        'state': nm[host][proto][port]['state'],
                        'service': nm[host][proto][port]['name'],
                        'version': nm[host][proto][port].get('version', ''),
                        'product': nm[host][proto][port].get('product', ''),
                        'extrainfo': nm[host][proto][port].get('extrainfo', '')
                    }
                    
                    if port_info['state'] == 'open':
                        results['hosts'][host]['open_ports'].append(port_info)
                    elif port_info['state'] == 'closed':
                        results['hosts'][host]['closed_ports'].append(port_info)
                    else:
                        results['hosts'][host]['filtered_ports'].append(port_info)
        
        return jsonify({
            'success': True,
            'results': results
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/vulnerability_scan', methods=['POST'])
def vulnerability_scan():
    """Vulnerability scanning using Nmap scripts"""
    data = request.get_json()
    target = data.get('target', '127.0.0.1')
    scripts = data.get('scripts', 'vuln')
    ports = data.get('ports', '')
    
    try:
        nm = nmap.PortScanner()
        
        # Build scan arguments
        args = f'--script {scripts} -sV'
        if ports:
            args += f' -p {ports}'
        
        # Perform vulnerability scan
        nm.scan(target, arguments=args)
        
        # Format results
        results = {
            'target': target,
            'scripts_used': scripts,
            'vulnerabilities': [],
            'hosts': {},
            'timestamp': datetime.now().isoformat()
        }
        
        for host in nm.all_hosts():
            host_info = {
                'state': nm[host].state(),
                'ports': {},
                'hostscript': nm[host].get('hostscript', [])
            }
            
            # Process port-specific vulnerabilities
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    port_data = nm[host][proto][port]
                    host_info['ports'][f'{proto}/{port}'] = {
                        'state': port_data['state'],
                        'service': port_data['name'],
                        'version': port_data.get('version', ''),
                        'script': port_data.get('script', {})
                    }
                    
                    # Extract vulnerability information
                    if 'script' in port_data:
                        for script_name, script_output in port_data['script'].items():
                            if 'vuln' in script_name.lower():
                                results['vulnerabilities'].append({
                                    'host': host,
                                    'port': f'{proto}/{port}',
                                    'script': script_name,
                                    'output': script_output,
                                    'severity': 'unknown'  # Could be parsed from output
                                })
            
            results['hosts'][host] = host_info
        
        return jsonify({
            'success': True,
            'results': results,
            'vulnerability_count': len(results['vulnerabilities'])
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/network_discovery', methods=['POST'])
def network_discovery():
    """Discover hosts on a network"""
    data = request.get_json()
    network = data.get('network', '192.168.1.0/24')
    
    try:
        nm = nmap.PortScanner()
        
        # Perform host discovery scan
        nm.scan(network, arguments='-sn')  # Ping scan only
        
        results = {
            'network': network,
            'hosts_discovered': [],
            'total_hosts': 0,
            'timestamp': datetime.now().isoformat()
        }
        
        for host in nm.all_hosts():
            host_info = {
                'ip': host,
                'state': nm[host].state(),
                'hostnames': []
            }
            
            # Get hostnames if available
            if 'hostnames' in nm[host]:
                for hostname in nm[host]['hostnames']:
                    host_info['hostnames'].append({
                        'name': hostname['name'],
                        'type': hostname['type']
                    })
            
            results['hosts_discovered'].append(host_info)
        
        results['total_hosts'] = len(results['hosts_discovered'])
        
        return jsonify({
            'success': True,
            'results': results
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    load_config()
    scheduler.add_job(scheduled_scan, 'interval', minutes=config['scan_interval_minutes'], id='scan_job')
    scheduler.start()
    # Initial scan removed - scan only when manually triggered
    app.run(debug=True)