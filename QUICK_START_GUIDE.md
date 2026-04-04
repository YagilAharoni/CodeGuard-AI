# Quick Start Guide for CodeGuardAI Application

## Prerequisites
- **Python 3.8+** installed (with virtual environment support)
- **Node.js 18+** installed (with npm)
- **Git** for cloning (if needed)

## Initial Setup (Starting from 0)

### 1. Clone or Navigate to Project Directory
```powershell
cd C:\Users\yagil\Projects\CodeGuardAI
```

### 2. Set Up Backend (FastAPI)
```powershell
# Create and activate virtual environment
python -m venv .venv
.venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt
```

### 3. Set Up Frontend (Next.js)
```powershell
# Navigate to frontend directory
cd my-security-ui

# Install Node.js dependencies
npm install

# Return to root directory
cd ..
```

## Starting the Application

### Start Backend (Port 8000)
```powershell
# Activate virtual environment (if not already active)
.venv\Scripts\activate

# Start FastAPI server
python app.py
```
- Backend will run on `http://localhost:8000`
- Keep this terminal open

### Start Frontend (Port 3000)
Open a new PowerShell terminal:
```powershell
# Navigate to frontend directory
cd C:\Users\yagil\Projects\CodeGuardAI\my-security-ui

# Start Next.js development server
npm run dev
```
- Frontend will run on `http://localhost:3000`
- Keep this terminal open

## Restarting Components

### Restart Backend
1. In the backend terminal, press `Ctrl+C` to stop the server
2. Restart with:
```powershell
python app.py
```

### Restart Frontend
1. In the frontend terminal, press `Ctrl+C` to stop the server
2. Restart with:
```powershell
npm run dev
```

## Handling Changes

### Backend Changes (Python files)
- **Automatic**: None - requires manual restart
- **When to restart**: After modifying `app.py`, `utils.py`, or any Python logic
- **How**: Stop and restart the backend as shown above

### Frontend Changes (React/TypeScript files)
- **Automatic**: Hot reload enabled - changes are applied instantly in browser
- **When to restart**: Rarely needed (only for config changes like `next.config.ts`)
- **How**: Stop and restart frontend if hot reload fails

### Dependency Changes
- **Backend**: After updating `requirements.txt`, reinstall:
```powershell
pip install -r requirements.txt
```
Then restart backend.

- **Frontend**: After updating `package.json`, reinstall:
```powershell
npm install
```
Then restart frontend.

## Troubleshooting
- If ports are in use, kill processes or change ports in code
- Check terminal output for error messages
- Ensure virtual environment is activated for backend
- Clear browser cache if frontend changes don't appear

## Full Restart Sequence
```powershell
# Backend
.venv\Scripts\activate
python app.py

# Frontend (new terminal)
cd my-security-ui
npm run dev
```