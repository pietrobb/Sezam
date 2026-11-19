@echo off
REM Git bundle backup — date-stamped to Z:\Backup\Sources\Sezam
setlocal

set BACKUP_DIR=Z:\Backup\Sources\Sezam
set TIMESTAMP=%date:~-4%%date:~-7,2%%date:~-10,2%_%time:~0,2%%time:~3,2%%time:~6,2%
set TIMESTAMP=%TIMESTAMP: =0%
set BUNDLE=%BACKUP_DIR%\sezam_%TIMESTAMP%.bundle

if not exist "%BACKUP_DIR%" mkdir "%BACKUP_DIR%"

git -C "%~dp0" bundle create "%BUNDLE%" --all
if %ERRORLEVEL% EQU 0 (
    echo Bundle created: %BUNDLE%
) else (
    echo ERROR: Bundle creation failed!
    exit /b 1
)
