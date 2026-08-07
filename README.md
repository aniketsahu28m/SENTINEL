# Sentinel

Sentinel is a network threat scanning platform with a Python backend and a React/Vite frontend.

## What Lives Where

- `backend/`: Flask API, scan orchestration, anomaly detection, and stored scan data
- `frontend/`: browser dashboard for monitoring and triggering scans
- `startup.bat`: Windows launcher for starting both services

## Requirements

- Python 3.12 or newer
- Node.js 18 or newer
- Nmap
- GnuPG

On macOS, install the missing command-line tools with Homebrew:

```bash
brew install python node nmap gnupg
```

## Setup

1. Backend

```bash
cd backend
python -m venv .venv
```

Activate the virtual environment before installing packages:

```bash
# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate
```

Then install dependencies and configure the backend environment:

```bash
pip install -r requirements.txt
```

Create a `.env` file in `backend/` for SMTP, GPG, and dashboard settings before starting the server.

2. Frontend

```bash
cd frontend
npm install
```

## Build

The backend does not have a build step. Build the frontend for production with:

```bash
cd frontend
npm run build
```

To preview the production build locally, run:

```bash
cd frontend
npm run preview
```

## Run

### Windows

Use the bundled launcher:

```bat
startup.bat
```

Or start the services manually in two terminals:

```bash
cd backend
.venv\Scripts\activate
python scanner.py
```

```bash
cd frontend
npm run dev
```

### macOS / Linux

Start the services manually in two terminals:

```bash
cd backend
source .venv/bin/activate
python scanner.py
```

```bash
cd frontend
npm run dev -- --host
```

Open the app in your browser at http://localhost:5173. The backend runs at http://localhost:5000.

## Tests

Run the backend test suite with standard library unittest:

```bash
cd backend
python -m unittest discover -s tests -p "test_*.py"
```

## Access

- Admin dashboard: http://localhost:5000
- User interface: http://localhost:5173

## Security Notes

- Configure PGP keys and SMTP credentials securely.
- Use environment variables for sensitive data.
- Run scans only on networks you are authorized to test.