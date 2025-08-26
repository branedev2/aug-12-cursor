package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

// True Positive Examples (Vulnerable Code)

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_1() {
	// Creating a file with overly permissive permissions (0666 - read/write for everyone)
	data := []byte("sensitive data")
	// ruleid: rule-poorwritepermissions-updatedMIT
	err := ioutil.WriteFile("sensitive_data.txt", data, 0666)
	if err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_2() {
	// Creating a file with world-writable permissions (0777)
	file, err := os.Create("config_file.ini")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	
	// ruleid: rule-poorwritepermissions-updatedMIT
	if err := os.Chmod("config_file.ini", 0777); err != nil {
		log.Fatal(err)
	}
	
	file.WriteString("password=secret123")
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_3() {
	// Creating a directory with overly permissive permissions
	// ruleid: rule-poorwritepermissions-updatedMIT
	err := os.Mkdir("sensitive_directory", 0777)
	if err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_4() {
	// Creating a file with permissions that allow group and others to write
	f, err := os.OpenFile("credentials.txt", os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	
	// ruleid: rule-poorwritepermissions-updatedMIT
	f.Chmod(0666)
	
	f.WriteString("API_KEY=abcdef123456")
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_5() {
	// Creating multiple files with insecure permissions
	data := []byte("private key data")
	
	// ruleid: rule-poorwritepermissions-updatedMIT
	if err := ioutil.WriteFile("private_key.pem", data, 0644); err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_6() {
	// Creating a temporary file with insecure permissions
	tempDir := os.TempDir()
	tempFile := filepath.Join(tempDir, "temp_credentials.txt")
	
	f, err := os.Create(tempFile)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	
	// ruleid: rule-poorwritepermissions-updatedMIT
	if err := os.Chmod(tempFile, 0666); err != nil {
		log.Fatal(err)
	}
	
	f.WriteString("database_password=db123")
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_7() {
	// Creating a file with permissions allowing others to read sensitive data
	file, err := os.OpenFile("user_data.json", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	
	// ruleid: rule-poorwritepermissions-updatedMIT
	file.Chmod(0644)
	
	file.WriteString(`{"username": "admin", "password": "admin123"}`)
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_8() {
	// MkdirAll with insecure permissions
	// ruleid: rule-poorwritepermissions-updatedMIT
	if err := os.MkdirAll("config/secrets", 0777); err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_9() {
	// Using a variable for permissions but still insecure
	mode := os.FileMode(0666)
	
	// ruleid: rule-poorwritepermissions-updatedMIT
	file, err := os.OpenFile("api_keys.txt", os.O_CREATE|os.O_WRONLY, mode)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	
	file.WriteString("API_KEY=xyz123")
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_10() {
	// Creating a file with permissions allowing group write access
	data := []byte("internal company data")
	
	// ruleid: rule-poorwritepermissions-updatedMIT
	err := ioutil.WriteFile("internal_data.txt", data, 0660)
	if err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_11() {
	// Creating a symbolic link with insecure permissions
	// ruleid: rule-poorwritepermissions-updatedMIT
	if err := os.Symlink("target", "symlink", 0777); err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_12() {
	// Using octal literal for permissions
	// ruleid: rule-poorwritepermissions-updatedMIT
	file, err := os.OpenFile("config.json", os.O_CREATE|os.O_WRONLY, 0777)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	
	file.WriteString(`{"debug": true}`)
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_13() {
	// Using a constant for permissions but still insecure
	const filePerms = 0666
	
	// ruleid: rule-poorwritepermissions-updatedMIT
	file, err := os.OpenFile("logs.txt", os.O_CREATE|os.O_APPEND|os.O_WRONLY, filePerms)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	
	file.WriteString("Log entry: Application started\n")
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_14() {
	// Creating a file with permissions allowing others to read
	// ruleid: rule-poorwritepermissions-updatedMIT
	file, err := os.Create("passwords.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	
	os.Chmod("passwords.txt", 0644)
	file.WriteString("password=secret123\n")
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
func bad_case_15() {
	// Creating a directory with permissions allowing group write
	// ruleid: rule-poorwritepermissions-updatedMIT
	if err := os.Mkdir("secure_files", 0774); err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_1() {
	// Creating a file with secure permissions (0600 - only owner can read/write)
	data := []byte("sensitive data")
	// ok: rule-poorwritepermissions-updatedMIT
	err := ioutil.WriteFile("sensitive_data.txt", data, 0600)
	if err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_2() {
	// Creating a file with secure permissions (0400 - only owner can read)
	file, err := os.Create("config_file.ini")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	
	file.WriteString("password=secret123")
	
	// ok: rule-poorwritepermissions-updatedMIT
	if err := os.Chmod("config_file.ini", 0400); err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_3() {
	// Creating a directory with secure permissions
	// ok: rule-poorwritepermissions-updatedMIT
	err := os.Mkdir("sensitive_directory", 0700)
	if err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_4() {
	// Creating a file with permissions that only allow owner to read/write
	// ok: rule-poorwritepermissions-updatedMIT
	f, err := os.OpenFile("credentials.txt", os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	
	f.WriteString("API_KEY=abcdef123456")
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_5() {
	// Creating a file with secure permissions for a private key
	data := []byte("private key data")
	
	// ok: rule-poorwritepermissions-updatedMIT
	if err := ioutil.WriteFile("private_key.pem", data, 0400); err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_6() {
	// Creating a temporary file with secure permissions
	tempDir := os.TempDir()
	tempFile := filepath.Join(tempDir, "temp_credentials.txt")
	
	// ok: rule-poorwritepermissions-updatedMIT
	f, err := os.OpenFile(tempFile, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	
	f.WriteString("database_password=db123")
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_7() {
	// Creating a file with secure permissions for sensitive data
	// ok: rule-poorwritepermissions-updatedMIT
	file, err := os.OpenFile("user_data.json", os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	
	file.WriteString(`{"username": "admin", "password": "admin123"}`)
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_8() {
	// MkdirAll with secure permissions
	// ok: rule-poorwritepermissions-updatedMIT
	if err := os.MkdirAll("config/secrets", 0700); err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_9() {
	// Using a variable for secure permissions
	mode := os.FileMode(0600)
	
	// ok: rule-poorwritepermissions-updatedMIT
	file, err := os.OpenFile("api_keys.txt", os.O_CREATE|os.O_WRONLY, mode)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	
	file.WriteString("API_KEY=xyz123")
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_10() {
	// Creating a read-only file with secure permissions
	data := []byte("internal company data")
	
	// ok: rule-poorwritepermissions-updatedMIT
	err := ioutil.WriteFile("internal_data.txt", data, 0400)
	if err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_11() {
	// Using a constant for secure permissions
	const securePerms = 0600
	
	// ok: rule-poorwritepermissions-updatedMIT
	file, err := os.OpenFile("secrets.txt", os.O_CREATE|os.O_WRONLY, securePerms)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	
	file.WriteString("secret=value")
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_12() {
	// Creating a directory with secure permissions for configuration files
	// ok: rule-poorwritepermissions-updatedMIT
	if err := os.Mkdir("config_dir", 0700); err != nil {
		log.Fatal(err)
	}
	
	configFile := filepath.Join("config_dir", "settings.conf")
	f, err := os.Create(configFile)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	
	f.WriteString("debug=false\n")
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_13() {
	// Using secure permissions for a log file that contains sensitive data
	// ok: rule-poorwritepermissions-updatedMIT
	logFile, err := os.OpenFile("audit.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()
	
	logFile.WriteString(fmt.Sprintf("Login attempt: %s\n", "username"))
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_14() {
	// Creating multiple files with secure permissions
	// ok: rule-poorwritepermissions-updatedMIT
	if err := os.MkdirAll("secure", 0700); err != nil {
		log.Fatal(err)
	}
	
	keyFile := filepath.Join("secure", "key.pem")
	if err := ioutil.WriteFile(keyFile, []byte("key data"), 0400); err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
func good_case_15() {
	// Creating a file with secure permissions and then writing to it
	// ok: rule-poorwritepermissions-updatedMIT
	file, err := os.OpenFile("database.conf", os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	
	file.WriteString("db_host=localhost\ndb_user=app\ndb_pass=secure_password\n")
}
// {/fact}

func main() {
	// This function is just a placeholder and doesn't need to be implemented
	fmt.Println("File permission examples")
}