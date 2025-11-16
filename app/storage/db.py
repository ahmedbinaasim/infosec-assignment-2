"""MySQL users table + salted hashing (no chat storage)."""
import os
import sys
import argparse
from typing import Optional, Tuple
import pymysql
from dotenv import load_dotenv
from app.common.utils import generate_salt, hash_password_with_salt, constant_time_compare


# Load environment variables
load_dotenv()


def get_db_connection():
    """
    Create and return a MySQL database connection.

    Reads configuration from environment variables:
    - MYSQL_HOST (default: localhost)
    - MYSQL_PORT (default: 3306)
    - MYSQL_USER (default: scuser)
    - MYSQL_PASSWORD (default: scpass)
    - MYSQL_DATABASE (default: securechat)

    Returns:
        pymysql.Connection object

    Raises:
        pymysql.Error: If connection fails
    """
    config = {
        'host': os.getenv('MYSQL_HOST', 'localhost'),
        'port': int(os.getenv('MYSQL_PORT', 3306)),
        'user': os.getenv('MYSQL_USER', 'scuser'),
        'password': os.getenv('MYSQL_PASSWORD', 'scpass'),
        'database': os.getenv('MYSQL_DATABASE', 'securechat'),
        'charset': 'utf8mb4',
        'cursorclass': pymysql.cursors.DictCursor,
        'autocommit': False
    }

    try:
        connection = pymysql.connect(**config)
        return connection
    except pymysql.Error as e:
        print(f"[ERROR] Failed to connect to MySQL: {e}")
        raise


def init_database():
    """
    Initialize the database by creating the users table.

    Table schema:
    - id: Auto-increment primary key
    - email: User email address
    - username: Unique username
    - salt: 16-byte random salt (VARBINARY)
    - pwd_hash: 64-character hex hash (CHAR)
    - created_at: Timestamp of account creation
    """
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            # Create users table
            create_table_query = """
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) NOT NULL,
                username VARCHAR(255) UNIQUE NOT NULL,
                salt VARBINARY(16) NOT NULL,
                pwd_hash CHAR(64) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_email (email),
                INDEX idx_username (username)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """

            cursor.execute(create_table_query)
            connection.commit()

            print("[SUCCESS] Database initialized successfully!")
            print("          Table 'users' created/verified.")

    except pymysql.Error as e:
        connection.rollback()
        print(f"[ERROR] Failed to initialize database: {e}")
        raise
    finally:
        connection.close()


def register_user(email: str, username: str, password: str) -> bool:
    """
    Register a new user with salted password hashing.

    Process:
    1. Check if username or email already exists
    2. Generate 16-byte random salt
    3. Compute pwd_hash = hex(SHA256(salt || password))
    4. Insert into database

    Args:
        email: User email address
        username: Unique username
        password: Plaintext password

    Returns:
        True if registration successful, False if user already exists

    Raises:
        pymysql.Error: If database operation fails
    """
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            # Check if username or email already exists
            check_query = """
            SELECT username, email FROM users
            WHERE username = %s OR email = %s
            """
            cursor.execute(check_query, (username, email))
            existing_user = cursor.fetchone()

            if existing_user:
                if existing_user['username'] == username:
                    print(f"[ERROR] Username '{username}' already exists")
                elif existing_user['email'] == email:
                    print(f"[ERROR] Email '{email}' already registered")
                return False

            # Generate random salt
            salt = generate_salt(16)

            # Compute salted password hash
            pwd_hash = hash_password_with_salt(password, salt)

            # Insert new user
            insert_query = """
            INSERT INTO users (email, username, salt, pwd_hash)
            VALUES (%s, %s, %s, %s)
            """
            cursor.execute(insert_query, (email, username, salt, pwd_hash))
            connection.commit()

            print(f"[SUCCESS] User '{username}' registered successfully!")
            return True

    except pymysql.Error as e:
        connection.rollback()
        print(f"[ERROR] Failed to register user: {e}")
        raise
    finally:
        connection.close()


def verify_login(email: str, password: str) -> bool:
    """
    Verify user login credentials using constant-time comparison.

    Process:
    1. Retrieve salt and pwd_hash for email
    2. Recompute hash using provided password and stored salt
    3. Use constant-time comparison to compare hashes (prevents timing attacks)

    Args:
        email: User email address
        password: Plaintext password to verify

    Returns:
        True if credentials valid, False otherwise
    """
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            # Retrieve user salt and password hash
            query = """
            SELECT salt, pwd_hash FROM users WHERE email = %s
            """
            cursor.execute(query, (email,))
            user = cursor.fetchone()

            if not user:
                print(f"[ERROR] User with email '{email}' not found")
                return False

            # Extract salt and stored hash
            salt = user['salt']
            stored_hash = user['pwd_hash']

            # Recompute hash with provided password
            computed_hash = hash_password_with_salt(password, salt)

            # Use constant-time comparison (critical for security!)
            # Convert strings to bytes for comparison
            match = constant_time_compare(
                stored_hash.encode('utf-8'),
                computed_hash.encode('utf-8')
            )

            if match:
                print(f"[SUCCESS] Login successful for '{email}'")
            else:
                print(f"[ERROR] Invalid password for '{email}'")

            return match

    except pymysql.Error as e:
        print(f"[ERROR] Database error during login: {e}")
        return False
    finally:
        connection.close()


def get_user_salt(email: str) -> Optional[bytes]:
    """
    Retrieve salt for a user (helper function for protocol).

    Args:
        email: User email address

    Returns:
        Salt bytes if user exists, None otherwise
    """
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            query = "SELECT salt FROM users WHERE email = %s"
            cursor.execute(query, (email,))
            user = cursor.fetchone()

            if user:
                return user['salt']
            return None

    except pymysql.Error as e:
        print(f"[ERROR] Failed to retrieve salt: {e}")
        return None
    finally:
        connection.close()


def get_user_info(email: str) -> Optional[dict]:
    """
    Retrieve user information (for debugging/testing).

    Args:
        email: User email address

    Returns:
        Dictionary with user info (excluding password hash) or None
    """
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            query = """
            SELECT id, email, username, created_at
            FROM users WHERE email = %s
            """
            cursor.execute(query, (email,))
            user = cursor.fetchone()
            return user

    except pymysql.Error as e:
        print(f"[ERROR] Failed to retrieve user info: {e}")
        return None
    finally:
        connection.close()


def list_users():
    """
    List all users in the database (for debugging/testing).

    Returns:
        List of user dictionaries
    """
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            query = """
            SELECT id, email, username, HEX(salt) as salt_hex,
                   pwd_hash, created_at
            FROM users
            ORDER BY created_at DESC
            """
            cursor.execute(query)
            users = cursor.fetchall()
            return users

    except pymysql.Error as e:
        print(f"[ERROR] Failed to list users: {e}")
        return []
    finally:
        connection.close()


# CLI interface
def main():
    parser = argparse.ArgumentParser(description="SecureChat Database Management")
    parser.add_argument('--init', action='store_true', help='Initialize database tables')
    parser.add_argument('--register', action='store_true', help='Register a new user')
    parser.add_argument('--login', action='store_true', help='Test user login')
    parser.add_argument('--list', action='store_true', help='List all users')
    parser.add_argument('--email', type=str, help='User email')
    parser.add_argument('--username', type=str, help='Username')
    parser.add_argument('--password', type=str, help='Password')

    args = parser.parse_args()

    if args.init:
        init_database()

    elif args.register:
        if not args.email or not args.username or not args.password:
            print("[ERROR] --register requires --email, --username, and --password")
            sys.exit(1)
        register_user(args.email, args.username, args.password)

    elif args.login:
        if not args.email or not args.password:
            print("[ERROR] --login requires --email and --password")
            sys.exit(1)
        success = verify_login(args.email, args.password)
        sys.exit(0 if success else 1)

    elif args.list:
        users = list_users()
        if users:
            print(f"\n{'ID':<5} {'Username':<20} {'Email':<30} {'Created'}")
            print("-" * 80)
            for user in users:
                print(f"{user['id']:<5} {user['username']:<20} {user['email']:<30} {user['created_at']}")
            print(f"\nTotal users: {len(users)}")
        else:
            print("No users found.")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()

