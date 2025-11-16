# Windows 10 Setup Notes for SecureChat Assignment

## Quick Reference for Windows Users

This document provides Windows-specific commands and notes for testing Section 2.2.

---

## Virtual Environment Commands (PowerShell)

```powershell
# Create virtual environment
python -m venv .venv

# Activate (PowerShell)
.venv\Scripts\Activate.ps1

# If you get execution policy error:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Deactivate
deactivate
```

---

## MySQL Setup (Local Installation)

### Create Database and User

**Option 1: MySQL Workbench (Recommended for beginners)**
1. Open MySQL Workbench
2. Connect to localhost
3. Run these commands in SQL tab:

```sql
CREATE DATABASE IF NOT EXISTS securechat;
CREATE USER IF NOT EXISTS 'scuser'@'localhost' IDENTIFIED BY 'scpass';
GRANT ALL PRIVILEGES ON securechat.* TO 'scuser'@'localhost';
FLUSH PRIVILEGES;
```

**Option 2: Command Line**
```powershell
# Connect as root
mysql -u root -p

# Then run the SQL commands above
```

### Test Connection

```powershell
mysql -u scuser -pscpass -e "SHOW DATABASES;"
```

---

## Common Commands Translation (Linux → Windows)

| Linux/Bash | Windows PowerShell |
|------------|-------------------|
| `cp file1 file2` | `Copy-Item file1 file2` |
| `cat file.txt` | `Get-Content file.txt` |
| `mkdir -p dir` | `New-Item -ItemType Directory -Force -Path dir` |
| `ls -la` | `Get-ChildItem` or `dir` |
| `pwd` | `Get-Location` or `pwd` |
| `source .venv/bin/activate` | `.venv\Scripts\Activate.ps1` |

---

## File Paths in Windows

- Use **backslashes** (`\`) or **forward slashes** (`/`) in paths
- For spaces in paths, use quotes: `"C:\Program Files\MySQL\..."`
- WSL path: `/mnt/c/Users/ahmed/...` → Windows: `C:\Users\ahmed\...`

---

## Running Python Modules

All commands work the same on Windows:

```powershell
# Test modules
python -m app.common.utils
python -m app.crypto.dh
python -m app.crypto.aes
python -m app.storage.db --init

# Database operations
python -m app.storage.db --register --email test@example.com --username testuser --password TestPass123
python -m app.storage.db --login --email test@example.com --password TestPass123
python -m app.storage.db --list
```

---

## Evidence Collection

### Create evidence directory
```powershell
New-Item -ItemType Directory -Force -Path evidence
```

### Export database inspection
```powershell
mysql -u scuser -pscpass securechat -e "SELECT id, username, email, HEX(salt) as salt_hex, pwd_hash, LENGTH(salt) as salt_length, LENGTH(pwd_hash) as hash_length, created_at FROM users;" > evidence/database_inspection.txt
```

### Export schema
```powershell
mysqldump -u scuser -pscpass --no-data securechat > evidence/schema.sql
```

---

## Common Issues & Solutions

### 1. MySQL Service Not Running

```powershell
# Check service status
Get-Service -Name MySQL*

# Start service (run as Administrator)
Start-Service -Name MySQL80

# Or use services.msc GUI
services.msc
```

### 2. PowerShell Execution Policy

```powershell
# Run PowerShell as Administrator
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### 3. MySQL Command Not Found

Either add MySQL to PATH or use full path:

```powershell
# Full path example (adjust version)
& "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" -u scuser -pscpass
```

To add to PATH permanently:
1. Search "Environment Variables" in Windows
2. Edit System Environment Variables
3. Add MySQL bin directory to PATH
4. Restart PowerShell

### 4. Python Import Errors

```powershell
# Make sure you're in project root
cd "C:\Users\ahmed\Documents\University\Semester 7\InfoSec\i220949_C_Assignment2\infosec-assignment-2"

# Activate virtual environment
.venv\Scripts\Activate.ps1

# Verify Python path
python -c "import sys; print(sys.executable)"

# Reinstall requirements
pip install --upgrade pip
pip install -r requirements.txt
```

---

## Text Editors for Windows

- **VS Code**: Recommended (built-in terminal, Python support)
- **Notepad++**: Good for quick edits
- **PyCharm**: Full IDE (heavier but powerful)
- **Notepad**: Basic, works for `.env` files

---

## Testing Checklist

- [ ] MySQL installed and running
- [ ] Python 3.x installed
- [ ] Virtual environment created and activated
- [ ] Dependencies installed (`pip install -r requirements.txt`)
- [ ] Database `securechat` created
- [ ] User `scuser` created with password `scpass`
- [ ] `.env` file created with correct credentials
- [ ] Database initialized (`python -m app.storage.db --init`)
- [ ] All unit tests pass
- [ ] Evidence files collected in `evidence/` directory

---

## Quick Test Script

Save this as `quick_test.ps1` and run to verify setup:

```powershell
# Quick setup verification script

Write-Host "`n=== SecureChat Setup Verification ===" -ForegroundColor Cyan

# Test 1: Python
Write-Host "`n[1] Testing Python..." -ForegroundColor Yellow
python --version

# Test 2: Virtual Environment
Write-Host "`n[2] Checking virtual environment..." -ForegroundColor Yellow
if (Test-Path ".venv\Scripts\python.exe") {
    Write-Host "  ✓ Virtual environment exists" -ForegroundColor Green
} else {
    Write-Host "  ✗ Virtual environment not found" -ForegroundColor Red
}

# Test 3: MySQL Connection
Write-Host "`n[3] Testing MySQL connection..." -ForegroundColor Yellow
mysql -u scuser -pscpass -e "SELECT 1;" 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✓ MySQL connection successful" -ForegroundColor Green
} else {
    Write-Host "  ✗ MySQL connection failed" -ForegroundColor Red
}

# Test 4: Database exists
Write-Host "`n[4] Checking securechat database..." -ForegroundColor Yellow
mysql -u scuser -pscpass -e "USE securechat; SELECT 1;" 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✓ Database 'securechat' exists" -ForegroundColor Green
} else {
    Write-Host "  ✗ Database 'securechat' not found" -ForegroundColor Red
}

# Test 5: .env file
Write-Host "`n[5] Checking .env file..." -ForegroundColor Yellow
if (Test-Path ".env") {
    Write-Host "  ✓ .env file exists" -ForegroundColor Green
} else {
    Write-Host "  ✗ .env file not found" -ForegroundColor Red
}

Write-Host "`n=== Verification Complete ===" -ForegroundColor Cyan
```

Run with:
```powershell
.\quick_test.ps1
```

---

## Additional Resources

- **MySQL Documentation**: https://dev.mysql.com/doc/
- **Python venv**: https://docs.python.org/3/library/venv.html
- **PowerShell Basics**: https://docs.microsoft.com/en-us/powershell/

---

For detailed testing instructions, see **TESTING_GUIDE_2.2.md**.
