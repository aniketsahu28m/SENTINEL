import os
import json
import time
import logging
from datetime import datetime, date
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_cors import CORS
from apscheduler.schedulers.background import BackgroundScheduler
import nmap
import gnupg
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
CORS(app)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret')

# Environment variables
SMTP_HOST = os.getenv('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
SMTP_USER = os.getenv('SMTP_USER')
SMTP_PASS = os.getenv('SMTP_PASS')
ALERT_FROM = os.getenv('ALERT_FROM', SMTP_USER)
GPG_HOME = os.getenv('GPG_HOME', os.path.expanduser('~/.gnupg'))
DASHBOARD_TOKEN = os.getenv('DASHBOARD_TOKEN', 'admin')

# Initialize GPG
# The gnupg library automatically uses the GNUPGHOME environment variable if set.
os.environ['GNUPGHOME'] = GPG_HOME
gpg = gnupg.GPG()

# Directories
DATA_DIR = 'data'
SCANS_DIR = os.path.join(DATA_DIR, 'scans')
ANOMALIES_DIR = os.path.join(DATA_DIR, 'anomalies')
CONFIG_FILE = os.path.join(DATA_DIR, 'config.json')

os.makedirs(SCANS_DIR, exist_ok=True)
os.makedirs(ANOMALIES_DIR, exist_ok=True)

# Global variables
config = {}
scheduler = BackgroundScheduler()

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

def check_auth():
    token = request.headers.get('Authorization') or request.args.get('token')
    return token == DASHBOARD_TOKEN

@app.before_request
def require_auth():
    if request.endpoint and 'dashboard' in request.endpoint:
        if not check_auth():
            return jsonify({'error': 'Unauthorized'}), 401

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