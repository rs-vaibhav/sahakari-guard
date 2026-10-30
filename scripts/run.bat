@echo off
REM One-command start for Windows: creates a virtual environment on first run,
REM installs dependencies and opens the dashboard on http://127.0.0.1:8000
cd /d "%~dp0\.."

if not exist .venv (
  echo Creating virtual environment (.venv)...
  py -3 -m venv .venv || python -m venv .venv
  .venv\Scripts\python -m pip install --upgrade pip
  .venv\Scripts\python -m pip install -r requirements.txt
)
set PYTHONUTF8=1
.venv\Scripts\python -m sahakari_guard serve %*
