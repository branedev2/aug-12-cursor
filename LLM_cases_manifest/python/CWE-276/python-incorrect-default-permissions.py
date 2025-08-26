import os
import stat
import tempfile
import shutil
import subprocess
from pathlib import Path


# True Positive Examples (Vulnerable Code)

# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_1():
    # Creating a file with overly permissive permissions (world-writable)
    # ruleid: python-incorrect-default-permissions
    with open("sensitive_data.txt", "w") as f:
        f.write("secret information")
    os.chmod("sensitive_data.txt", 0o666)  # Read and write for all users


# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_2():
    # Creating a directory with overly permissive permissions
    # ruleid: python-incorrect-default-permissions
    os.mkdir("config_directory")
    os.chmod("config_directory", 0o777)  # Full permissions for all users


# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_3():
    # Using os.open with unsafe permissions
    # ruleid: python-incorrect-default-permissions
    fd = os.open("credentials.txt", os.O_CREAT | os.O_WRONLY, 0o644)
    os.write(fd, b"username:password123")
    os.close(fd)


# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_4():
    # Using default permissions when creating a file with sensitive content
    # ruleid: python-incorrect-default-permissions
    with open("api_keys.json", "w") as f:
        f.write('{"api_key": "secret_key_value"}')
    # No explicit chmod, relying on default umask which might be too permissive


# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_5():
    # Creating a temporary file with explicit unsafe permissions
    # ruleid: python-incorrect-default-permissions
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    temp_file.write(b"sensitive temporary data")
    temp_file.close()
    os.chmod(temp_file.name, 0o666)


# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_6():
    # Using pathlib with unsafe permissions
    # ruleid: python-incorrect-default-permissions
    path = Path("secret_tokens.txt")
    path.write_text("oauth_token=abc123")
    path.chmod(0o644)  # World-readable


# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_7():
    # Creating multiple files with unsafe permissions
    # ruleid: python-incorrect-default-permissions
    for i in range(3):
        filename = f"user_data_{i}.txt"
        with open(filename, "w") as f:
            f.write(f"User {i} private data")
        os.chmod(filename, 0o777)  # Full permissions for everyone


# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_8():
    # Using umask but still setting unsafe permissions
    # ruleid: python-incorrect-default-permissions
    old_mask = os.umask(0o022)  # Still allows world-read
    try:
        with open("financial_data.csv", "w") as f:
            f.write("income,expenses,savings")
    finally:
        os.umask(old_mask)


# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_9():
    # Creating a directory structure with unsafe permissions
    # ruleid: python-incorrect-default-permissions
    os.makedirs("user/settings/private", exist_ok=True)
    os.chmod("user/settings/private", 0o755)  # World-readable


# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_10():
    # Using stat constants but still setting unsafe permissions
    # ruleid: python-incorrect-default-permissions
    with open("database_config.ini", "w") as f:
        f.write("[database]\npassword=db_password123")
    os.chmod("database_config.ini", stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)  # World-readable


# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_11():
    # Creating a file with mode parameter but unsafe permissions
    # ruleid: python-incorrect-default-permissions
    with open("encryption_keys.txt", "w", mode=0o644) as f:
        f.write("encryption_key=secret_key_123")


# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_12():
    # Using shutil with unsafe permissions
    # ruleid: python-incorrect-default-permissions
    with open("source_file.txt", "w") as f:
        f.write("sensitive source data")
    shutil.copy2("source_file.txt", "destination_file.txt")
    os.chmod("destination_file.txt", 0o666)


# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_13():
    # Using subprocess to create a file with unsafe permissions
    # ruleid: python-incorrect-default-permissions
    subprocess.run(["touch", "subprocess_file.txt"])
    os.chmod("subprocess_file.txt", 0o777)


# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_14():
    # Using a variable to store permissions but still unsafe
    # ruleid: python-incorrect-default-permissions
    permissions = 0o644  # World-readable
    with open("auth_tokens.txt", "w") as f:
        f.write("auth_token=secret_token_456")
    os.chmod("auth_tokens.txt", permissions)


# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_15():
    # Creating a temporary directory with unsafe permissions
    # ruleid: python-incorrect-default-permissions
    temp_dir = tempfile.mkdtemp()
    os.chmod(temp_dir, 0o777)  # Full permissions for everyone


# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_1():
    # Creating a file with secure permissions
    # ok: python-incorrect-default-permissions
    with open("sensitive_data_secure.txt", "w") as f:
        f.write("secret information")
    os.chmod("sensitive_data_secure.txt", 0o600)  # Read and write only for owner


# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_2():
    # Creating a directory with secure permissions
    # ok: python-incorrect-default-permissions
    os.mkdir("secure_config_directory")
    os.chmod("secure_config_directory", 0o700)  # Full permissions only for owner


# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_3():
    # Using os.open with secure permissions
    # ok: python-incorrect-default-permissions
    fd = os.open("secure_credentials.txt", os.O_CREAT | os.O_WRONLY, 0o600)
    os.write(fd, b"username:password123")
    os.close(fd)


# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_4():
    # Setting secure permissions explicitly after file creation
    # ok: python-incorrect-default-permissions
    with open("secure_api_keys.json", "w") as f:
        f.write('{"api_key": "secret_key_value"}')
    os.chmod("secure_api_keys.json", 0o600)  # Secure permissions


# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_5():
    # Creating a temporary file with secure permissions
    # ok: python-incorrect-default-permissions
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    temp_file.write(b"sensitive temporary data")
    temp_file.close()
    os.chmod(temp_file.name, 0o600)  # Secure permissions


# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_6():
    # Using pathlib with secure permissions
    # ok: python-incorrect-default-permissions
    path = Path("secure_tokens.txt")
    path.write_text("oauth_token=abc123")
    path.chmod(0o600)  # Only owner can read/write


# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_7():
    # Creating multiple files with secure permissions
    # ok: python-incorrect-default-permissions
    for i in range(3):
        filename = f"secure_user_data_{i}.txt"
        with open(filename, "w") as f:
            f.write(f"User {i} private data")
        os.chmod(filename, 0o600)  # Secure permissions


# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_8():
    # Using umask to set secure default permissions
    # ok: python-incorrect-default-permissions
    old_mask = os.umask(0o077)  # No permissions for group or others
    try:
        with open("secure_financial_data.csv", "w") as f:
            f.write("income,expenses,savings")
    finally:
        os.umask(old_mask)


# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_9():
    # Creating a directory structure with secure permissions
    # ok: python-incorrect-default-permissions
    os.makedirs("secure_user/settings/private", exist_ok=True)
    os.chmod("secure_user/settings/private", 0o700)  # Only owner has access


# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_10():
    # Using stat constants for secure permissions
    # ok: python-incorrect-default-permissions
    with open("secure_database_config.ini", "w") as f:
        f.write("[database]\npassword=db_password123")
    os.chmod("secure_database_config.ini", stat.S_IRUSR | stat.S_IWUSR)  # Only owner can read/write


# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_11():
    # Creating a file with secure mode parameter
    # ok: python-incorrect-default-permissions
    with open("secure_encryption_keys.txt", "w") as f:
        f.write("encryption_key=secret_key_123")
    os.chmod("secure_encryption_keys.txt", 0o600)


# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_12():
    # Using shutil with secure permissions
    # ok: python-incorrect-default-permissions
    with open("secure_source_file.txt", "w") as f:
        f.write("sensitive source data")
    shutil.copy2("secure_source_file.txt", "secure_destination_file.txt")
    os.chmod("secure_destination_file.txt", 0o600)


# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_13():
    # Using subprocess to create a file with secure permissions
    # ok: python-incorrect-default-permissions
    subprocess.run(["touch", "secure_subprocess_file.txt"])
    os.chmod("secure_subprocess_file.txt", 0o600)


# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_14():
    # Using a variable to store secure permissions
    # ok: python-incorrect-default-permissions
    secure_permissions = 0o600  # Only owner can read/write
    with open("secure_auth_tokens.txt", "w") as f:
        f.write("auth_token=secret_token_456")
    os.chmod("secure_auth_tokens.txt", secure_permissions)


# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_15():
    # Creating a temporary directory with secure permissions
    # ok: python-incorrect-default-permissions
    temp_dir = tempfile.mkdtemp()
    os.chmod(temp_dir, 0o700)  # Only owner has access
# {/fact}