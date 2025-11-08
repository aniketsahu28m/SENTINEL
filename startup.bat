@echo off
ECHO "Starting Sentinel..."

REM Start the backend server in a new window
ECHO "Starting backend server..."
cd backend
START "Sentinel Backend" wsl python3 scanner.py

REM Go back to root and into the frontend directory
cd ..
cd frontend

REM Start the frontend development server in a new window
ECHO "Starting frontend development server..."
START "Sentinel Frontend" npm run dev

REM Wait for the servers to start up (adjust time if needed)
ECHO "Waiting for servers to start..."
timeout /t 15

REM Open the frontend application in the default browser
ECHO "Opening application in browser..."
start http://localhost:5173

ECHO "Startup complete."
