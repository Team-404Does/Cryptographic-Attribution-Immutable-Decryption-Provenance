@echo off
rem Windows launcher for the SIH PQC attribution system.
rem Usage: run.bat [setup|backend|demo|desktop|test]
setlocal
set ROOT=%~dp0
set PY=%ROOT%.venv\Scripts\python.exe

if "%~1"=="" goto demo
if /i "%~1"=="setup" goto setup
if /i "%~1"=="backend" goto backend
if /i "%~1"=="demo" goto demo
if /i "%~1"=="desktop" goto desktop
if /i "%~1"=="test" goto test
echo usage: run.bat [setup^|backend^|demo^|desktop^|test]
exit /b 1

:setup
"%PY%" -m pip install -q -r "%ROOT%requirements.txt"
pushd "%ROOT%frontend"
call npm install --no-audit --no-fund
call npm run build
popd
goto :eof

:backend
pushd "%ROOT%backend"
"%PY%" -m uvicorn app.main:app --host 127.0.0.1 --port 8765
popd
goto :eof

:demo
pushd "%ROOT%backend"
set SIH_DEMO=1
"%PY%" -m uvicorn app.main:app --host 127.0.0.1 --port 8765
popd
goto :eof

:desktop
if not exist "%ROOT%frontend\dist" call %~0 setup
pushd "%ROOT%frontend"
call npx electron .
popd
goto :eof

:test
"%PY%" -m pytest "%ROOT%backend\tests" -q
goto :eof
