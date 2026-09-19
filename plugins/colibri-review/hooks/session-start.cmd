@echo off
rem SessionStart scan-ladder doctrine injection: stdout becomes session
rem context (same mechanism the superpowers and repo-memory plugins use).
rem A failed `type` must not block the session - guard with exit /b 0.
type "%~dp0doctrine.md" 2>nul
exit /b 0
