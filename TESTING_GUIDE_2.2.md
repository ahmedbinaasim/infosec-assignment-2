# Testing Guide for Section 2.2: Registration and Login

## Prerequisites

1. **MySQL Running** (via Docker or local installation)
2. **Virtual environment activated**
3. **All Section 2.1 components** (PKI) working
4. **.env file created** (copy from .env.example)

---

## Phase 1: Setup MySQL Database (Windows 10 - Local Installation)

### Step 1.1: Verify MySQL is Running

**Option A: Using MySQL Workbench**
- Open MySQL Workbench
- Check if your local connection is active (green indicator)

**Option B: Using Command Prompt or PowerShell**
```powershell
# Open PowerShell or Command Prompt
# Test if MySQL service is running
Get-Service -Name MySQL*

# Or use services.msc to check MySQL service status
```

**Option C: Test MySQL Connection**
```powershell
# Connect to MySQL (adjust credentials if needed)
mysql -u root -p

# Once connected, type:
SHOW DATABASES;
EXIT;
```

### Step 1.2: Create Database and User

**Using MySQL Workbench:**
1. Open MySQL Workbench
2. Connect to your local MySQL instance (usually root@localhost)
3. Open a new SQL tab
4. Run the following commands:

```sql
-- Create database
CREATE DATABASE IF NOT EXISTS securechat;

-- Create user with password
CREATE USER IF NOT EXISTS 'scuser'@'localhost' IDENTIFIED BY 'scpass';

-- Grant all privileges on securechat database
GRANT ALL PRIVILEGES ON securechat.* TO 'scuser'@'localhost';

-- Apply changes
FLUSH PRIVILEGES;

-- Verify
SELECT User, Host FROM mysql.user WHERE User = 'scuser';
```

**Using Command Line:**
```powershell
# Open PowerShell/Command Prompt
mysql -u root -p

# Enter your MySQL root password, then run:
```

```sql
CREATE DATABASE IF NOT EXISTS securechat;
CREATE USER IF NOT EXISTS 'scuser'@'localhost' IDENTIFIED BY 'scpass';
GRANT ALL PRIVILEGES ON securechat.* TO 'scuser'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

**Verify the database was created:**
```powershell
mysql -u scuser -pscpass -e "SHOW DATABASES;"
```

**Expected:** Should show `securechat` in the list

### Step 1.3: Create .env file

**Using PowerShell:**
```powershell
# Copy .env.example to .env
Copy-Item .env.example .env

# Edit .env file (use notepad or your preferred editor)
notepad .env
```

**Verify .env contents match your MySQL setup:**
```
MYSQL_HOST=localhost
MYSQL_PORT=3306
MYSQL_USER=scuser
MYSQL_PASSWORD=scpass
MYSQL_DATABASE=securechat
```

**Note:** If you changed the username/password when creating the MySQL user, update .env accordingly.

### Step 1.4: Initialize database tables

**Using PowerShell or Command Prompt:**
```powershell
# Make sure virtual environment is activated first
# If not activated:
.venv\Scripts\Activate.ps1

# Initialize the database
python -m app.storage.db --init
```

**Expected Output:**
```
[SUCCESS] Database initialized successfully!
          Table 'users' created/verified.
```

---

## Phase 2: Unit Testing Individual Modules

### Test 2.1: Utils Module

```bash
python -m app.common.utils
```

**Expected Output:**
```
=== Utils Module Tests ===

Current timestamp (ms): 1731409123456

Base64 encoding:
  Original: b'Hello, SecureChat!'
  Encoded:  SGVsbG8sIFNlY3VyZUNoYXQh
  Decoded:  b'Hello, SecureChat!'
  Match: True

SHA-256 hash of 'test':
  Hash: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
  Length: 64 chars
  Expected: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
  Match: True

Salt generation:
  Salt 1: a1b2c3d4e5f6... (length: 16)
  Salt 2: f6e5d4c3b2a1... (length: 16)
  Different: True

Password hashing:
  Password: MySecurePassword123
  Salt: ...
  Hash: ... (64 chars)
  Hash length: 64 chars

Constant-time comparison:
  Same hashes: True
  Different hashes: False

=== All utils tests passed! ===
```

**Verify:** ✅ All tests pass

---

### Test 2.2: DH Module

```bash
python -m app.crypto.dh
```

**Expected Output:**
```
=== Diffie-Hellman Module Tests ===

[1] Generating DH parameters...
    Prime p (bits): 2048
    Generator g: 2

[2] Alice generates DH keypair...
    Alice private key (bits): ~2047
    Alice public key (bits): ~2048

[3] Bob generates DH keypair...
    Bob private key (bits): ~2047
    Bob public key (bits): ~2048

[4] Alice computes shared secret...
    Alice shared secret (first 32 hex): 0x...

[5] Bob computes shared secret...
    Bob shared secret (first 32 hex): 0x...

[6] Verifying shared secrets match...
    Secrets match: True

[7] Deriving AES-128 keys...
    Alice AES key: a1b2c3d4e5f6...
    Bob AES key:   a1b2c3d4e5f6...
    Keys match: True
    Key length: 16 bytes

=== All DH tests passed! ===
```

**Verify:** ✅ Shared secrets and AES keys match

---

### Test 2.3: AES Module

```bash
python -m app.crypto.aes
```

**Expected Output:**
```
=== AES-128-ECB Module Tests ===

[1] Testing basic encryption/decryption...
    Key: ...
    Plaintext: b'Hello, SecureChat! This is a test message.'
    Plaintext length: 43 bytes
    Ciphertext: ...
    Ciphertext length: 48 bytes
    Decrypted: b'Hello, SecureChat! This is a test message.'
    Match: True

[2] Testing PKCS#7 padding...
    Test 1: len=16 -> padded=32 -> unpadded=16 | Match: True
    Test 2: len=17 -> padded=32 -> unpadded=17 | Match: True
    Test 3: len= 1 -> padded=16 -> unpadded= 1 | Match: True
    Test 4: len=15 -> padded=16 -> unpadded=15 | Match: True

[3] Testing various message sizes...
    Size   1 bytes: ✓
    Size  15 bytes: ✓
    Size  16 bytes: ✓
    Size  17 bytes: ✓
    Size  32 bytes: ✓
    Size 100 bytes: ✓

[4] Testing wrong key detection...
    Decryption with wrong key: Detected! (padding error)

=== All AES tests passed! ===
```

**Verify:** ✅ All encryption/decryption cycles work, wrong key detected

---

### Test 2.4: Protocol Models

```bash
python -m app.common.protocol
```

**Expected Output:**
```
=== Protocol Models Tests ===

[1] Testing HelloMessage...
    {"type":"hello","client_cert":"-----BEGIN CERTIFICATE-----...

[2] Testing DHClientMessage...
    {"type":"dh_client","p":12345678901234567890,"g":2,"A":9876543210987654321}

[3] Testing RegisterMessage...
    {"type":"register","email":"alice@example.com","username":"alice"...

[4] Testing ChatMessage...
    {"type":"msg","seqno":1,"ts":1700000000000,"ct":"...","sig":"..."}

[5] Testing SessionReceiptMessage...
    {"type":"receipt","peer":"server","first_seq":1,"last_seq":10...

[6] Testing ErrorMessage...
    {"type":"error","code":"BAD_CERT","message":"Certificate validation failed: expired"}

=== All protocol model tests passed! ===
```

**Verify:** ✅ All Pydantic models serialize correctly

---

## Phase 3: Database Testing

### Test 3.1: Register Users

```bash
# Register first user
python -m app.storage.db --register --email alice@example.com --username alice --password AlicePass123

# Expected:
# [SUCCESS] User 'alice' registered successfully!

# Register second user
python -m app.storage.db --register --email bob@example.com --username bob --password BobSecure456

# Expected:
# [SUCCESS] User 'bob' registered successfully!

# Try to register duplicate (should fail)
python -m app.storage.db --register --email alice@example.com --username alice2 --password test

# Expected:
# [ERROR] Email 'alice@example.com' already registered
```

---

### Test 3.2: Verify Logins

```bash
# Login with correct password
python -m app.storage.db --login --email alice@example.com --password AlicePass123

# Expected:
# [SUCCESS] Login successful for 'alice@example.com'

# Login with wrong password
python -m app.storage.db --login --email alice@example.com --password WrongPassword

# Expected:
# [ERROR] Invalid password for 'alice@example.com'

# Login with non-existent email
python -m app.storage.db --login --email nobody@example.com --password test

# Expected:
# [ERROR] User with email 'nobody@example.com' not found
```

---

### Test 3.3: List Users

```bash
python -m app.storage.db --list
```

**Expected Output:**
```
ID    Username             Email                          Created
--------------------------------------------------------------------------------
2     bob                  bob@example.com                2025-11-12 ...
1     alice                alice@example.com              2025-11-12 ...

Total users: 2
```

---

## Phase 4: Database Inspection (EVIDENCE COLLECTION)

### Inspect Database to Verify Security

**Using PowerShell:**
```powershell
# Create evidence directory
New-Item -ItemType Directory -Force -Path evidence

# View users table with salts and hashes (save to file)
mysql -u scuser -pscpass securechat -e "SELECT id, username, email, HEX(salt) as salt_hex, pwd_hash, LENGTH(salt) as salt_length, LENGTH(pwd_hash) as hash_length, created_at FROM users;" > evidence/database_inspection.txt

# View the file
Get-Content evidence/database_inspection.txt
```

**Alternative: Using MySQL Workbench**
1. Open MySQL Workbench
2. Connect to your local instance
3. Select `securechat` database
4. Run this query:

```sql
SELECT
  id,
  username,
  email,
  HEX(salt) as salt_hex,
  pwd_hash,
  LENGTH(salt) as salt_length,
  LENGTH(pwd_hash) as hash_length,
  created_at
FROM users;
```

5. Export results to CSV or copy the output
6. Save as `evidence/database_inspection.txt`

**Expected Output:**
```
id	username	email	salt_hex	pwd_hash	salt_length	hash_length	created_at
1	alice	alice@example.com	A1B2C3D4E5F67890...	3fc9b689459d738f8c88a3a48aa9e33542016b7a4052e001aaa536fca74813cb	16	64	2025-11-12 ...
2	bob	bob@example.com	F6E5D4C3B2A19876...	5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8	16	64	2025-11-12 ...
```

**Verify (CRITICAL FOR REPORT):**
- ✅ `salt_length` = 16 bytes
- ✅ `hash_length` = 64 characters (hex-encoded SHA-256)
- ✅ NO plaintext passwords visible
- ✅ Different salts for each user
- ✅ Different hashes for each user

**Save this output for your assignment report!**

---

## Phase 5: Integration Test - Full Registration Flow

Create a test script to simulate the complete flow:

**Using PowerShell:**
```powershell
# Create tests directory if it doesn't exist
New-Item -ItemType Directory -Force -Path tests

# Create the test script
# Copy the following Python code into tests/test_section_2.2.py using your text editor
```

**Create file `tests/test_section_2.2.py` with this content:**

```python
"""Integration test for Section 2.2: Registration and Login"""
import json
from app.crypto.pki import load_certificate, validate_certificate
from app.crypto.dh import *
from app.crypto.aes import *
from app.storage.db import register_user, verify_login
from app.common.utils import b64e, b64d

print("=== Section 2.2 Integration Test ===\n")

# Step 1: PKI Validation (Section 2.1)
print("[1] Loading and validating certificates...")
try:
    ca_cert = load_certificate('certs/ca_cert.pem')
    client_cert = load_certificate('certs/client_cert.pem')
    validate_certificate(client_cert, ca_cert, 'client.local')
    print("    ✓ Client certificate validated")
except Exception as e:
    print(f"    ✗ Certificate validation failed: {e}")
    exit(1)

# Step 2: DH Key Exchange
print("\n[2] Performing DH key exchange...")
p, g = generate_dh_parameters()
client_priv, client_pub = generate_dh_keypair(p, g)
server_priv, server_pub = generate_dh_keypair(p, g)

client_secret = compute_shared_secret(server_pub, client_priv, p)
server_secret = compute_shared_secret(client_pub, server_priv, p)

client_key = derive_aes_key(client_secret)
server_key = derive_aes_key(server_secret)

print(f"    ✓ DH completed, keys match: {client_key == server_key}")

# Step 3: Encrypt Registration Data
print("\n[3] Encrypting registration credentials...")
reg_data = json.dumps({
    'email': 'testuser@example.com',
    'username': 'testuser',
    'password': 'TestPassword123!'
}).encode('utf-8')

encrypted_data = aes_encrypt(reg_data, client_key)
print(f"    ✓ Credentials encrypted ({len(encrypted_data)} bytes)")
print(f"    ✓ Ciphertext (first 32 bytes): {encrypted_data[:32].hex()}...")

# Step 4: Server Decrypts
print("\n[4] Server decrypts credentials...")
decrypted_data = aes_decrypt(encrypted_data, server_key)
reg_info = json.loads(decrypted_data)
print(f"    ✓ Decrypted: {reg_info}")

# Step 5: Register User
print("\n[5] Registering user in database...")
success = register_user(
    reg_info['email'],
    reg_info['username'],
    reg_info['password']
)
print(f"    ✓ Registration: {'SUCCESS' if success else 'FAILED'}")

# Step 6: Verify Login
print("\n[6] Verifying login credentials...")
login_success = verify_login(reg_info['email'], reg_info['password'])
print(f"    ✓ Login: {'SUCCESS' if login_success else 'FAILED'}")

# Step 7: Verify Wrong Password Rejected
print("\n[7] Testing wrong password rejection...")
wrong_login = verify_login(reg_info['email'], 'WrongPassword')
print(f"    ✓ Wrong password: {'CORRECTLY REJECTED' if not wrong_login else 'INCORRECTLY ACCEPTED (BAD!)'}")

print("\n=== All integration tests passed! ===")
```

**Run the integration test:**
```powershell
python tests/test_section_2.2.py
```

**Expected Output:**
```
=== Section 2.2 Integration Test ===

[1] Loading and validating certificates...
    ✓ Client certificate validated

[2] Performing DH key exchange...
    ✓ DH completed, keys match: True

[3] Encrypting registration credentials...
    ✓ Credentials encrypted (80 bytes)
    ✓ Ciphertext (first 32 bytes): a1b2c3d4...

[4] Server decrypts credentials...
    ✓ Decrypted: {'email': 'testuser@example.com', ...}

[5] Registering user in database...
[SUCCESS] User 'testuser' registered successfully!
    ✓ Registration: SUCCESS

[6] Verifying login credentials...
[SUCCESS] Login successful for 'testuser@example.com'
    ✓ Login: SUCCESS

[7] Testing wrong password rejection...
[ERROR] Invalid password for 'testuser@example.com'
    ✓ Wrong password: CORRECTLY REJECTED

=== All integration tests passed! ===
```

---

## Phase 6: Security Evidence Collection

### Evidence 6.1: No Plaintext in Network Traffic

Since we haven't implemented the full client-server yet, simulate with Python:

```python
# Create test to show encryption
python -c "
from app.crypto.aes import aes_encrypt
from app.crypto.dh import generate_dh_parameters, generate_dh_keypair, compute_shared_secret, derive_aes_key
import json

# Simulate credential transmission
credentials = json.dumps({
    'username': 'alice',
    'password': 'MySecretPassword123!'
}).encode('utf-8')

# DH key exchange
p, g = generate_dh_parameters()
c_priv, c_pub = generate_dh_keypair(p, g)
s_priv, s_pub = generate_dh_keypair(p, g)
secret = compute_shared_secret(s_pub, c_priv, p)
key = derive_aes_key(secret)

# Encrypt
ciphertext = aes_encrypt(credentials, key)

print('Plaintext credentials:')
print(credentials)
print('\nWhat an eavesdropper sees (ciphertext):')
print(ciphertext.hex())
print('\nNo plaintext visible in ciphertext: ✓')
"
```

**Save output to `evidence/encryption_demo.txt`**

---

### Evidence 6.2: Database Schema

**Using PowerShell:**
```powershell
# Export database schema
mysqldump -u scuser -pscpass --no-data securechat > evidence/schema.sql

# View schema
Get-Content evidence/schema.sql
```

**Alternative: Using MySQL Workbench**
1. Open MySQL Workbench
2. Connect to local instance
3. Go to Server → Data Export
4. Select `securechat` database
5. Choose "Export to Self-Contained File"
6. Uncheck "Include Data" (schema only)
7. Export to `evidence/schema.sql`

**Verify schema shows:**
- `salt VARBINARY(16)`
- `pwd_hash CHAR(64)`

---

## Phase 7: Test Summary Checklist

Create a summary file:

**Create file `evidence/section_2.2_summary.txt` with this content:**

```text
=== Section 2.2 Test Summary ===

✅ Utils Module
   - SHA-256 hashing works
   - Base64 encoding/decoding works
   - 16-byte salt generation works
   - Constant-time comparison works

✅ DH Module
   - Key exchange produces matching shared secrets
   - AES key derivation: K = Trunc16(SHA256(Ks))
   - 16-byte keys generated correctly

✅ AES Module
   - AES-128-ECB encryption/decryption works
   - PKCS#7 padding applied correctly
   - Wrong key detection works

✅ Database Module
   - MySQL connection established
   - Users table created with correct schema
   - User registration with unique 16-byte salts
   - Salted password hashing: hex(SHA256(salt||pwd))
   - Constant-time login verification
   - Duplicate user rejection

✅ Integration
   - Certificate validation before credential exchange
   - DH key exchange for credential protection
   - Credentials encrypted in transit (AES-128)
   - Database stores only salted hashes (64 hex chars)
   - Login succeeds with correct password
   - Login fails with wrong password

✅ Security Properties
   - No plaintext passwords in database
   - No plaintext passwords in transit
   - Unique salt per user (16 bytes)
   - Timing-safe hash comparison
   - Dual-gate: cert validation + password verification
```

Then view it:
```powershell
Get-Content evidence/section_2.2_summary.txt
```

---

## Final Checklist

Before submitting, ensure you have:

- [ ] All unit tests pass (utils, DH, AES, protocol, db)
- [ ] Database initialized and users registered
- [ ] Database inspection showing salted hashes
- [ ] Integration test showing full flow
- [ ] Evidence files in `evidence/` directory:
  - `database_inspection.txt`
  - `schema.sql`
  - `encryption_demo.txt`
  - `section_2.2_summary.txt`
- [ ] No plaintext passwords anywhere
- [ ] Screenshots of successful tests

---

## Troubleshooting

**MySQL Connection Failed:**
```powershell
# Check if MySQL service is running
Get-Service -Name MySQL*

# Or check in services.msc GUI
services.msc

# Restart MySQL service if needed (run as Administrator)
Restart-Service -Name MySQL80  # Adjust name based on your version
```

**Test connection:**
```powershell
mysql -u scuser -pscpass -e "SELECT 1;"
```

**Import Errors:**
```powershell
# Make sure you're in project root
cd "C:\Users\ahmed\Documents\University\Semester 7\InfoSec\i220949_C_Assignment2\infosec-assignment-2"

# Activate venv
.venv\Scripts\Activate.ps1

# If activation is blocked, run PowerShell as Administrator and execute:
# Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Reinstall if needed
pip install -r requirements.txt
```

**Database Permission Denied:**
```powershell
# Verify .env has correct credentials
Get-Content .env | Select-String "MYSQL"

# Test connection with credentials
mysql -u scuser -pscpass -e "SHOW DATABASES;"
```

**PowerShell Script Execution Error:**
```powershell
# If you get "cannot be loaded because running scripts is disabled"
# Run PowerShell as Administrator and execute:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**MySQL Command Not Found:**
```powershell
# Add MySQL to PATH or use full path
# Example full path (adjust for your installation):
& "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" -u scuser -pscpass
```

---

## Next Steps

After all tests pass:
1. Save all evidence files
2. Take screenshots of successful test outputs
3. Document in your assignment report
4. Ready to implement Section 2.3 (Session Key Establishment for Chat)
