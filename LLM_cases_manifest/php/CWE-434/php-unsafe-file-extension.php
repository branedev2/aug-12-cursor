<?php
// {fact rule=unrestricted-file-upload@v1.0 defects=1}
// PHP Unsafe File Extension Examples

// TRUE POSITIVES (Vulnerable Code)

// Example 1: Basic file upload without extension validation
function bad_case_1() {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $uploaddir = '/var/www/uploads/';
        $uploadfile = $uploaddir . basename($_FILES['userfile']['name']);
        
        // ruleid: php-unsafe-file-extension
        if (move_uploaded_file($_FILES['userfile']['tmp_name'], $uploadfile)) {
            echo "File is valid, and was successfully uploaded.\n";
        } else {
            echo "Upload failed.\n";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

// Example 2: Checking file size but not extension
function bad_case_2() {
    if (isset($_FILES['document'])) {
        $file = $_FILES['document'];
        
        // Only checking file size, not extension
        if ($file['size'] <= 1000000) {
            $destination = "/var/www/html/uploads/" . $file['name'];
            // ruleid: php-unsafe-file-extension
            move_uploaded_file($file['tmp_name'], $destination);
            echo "Upload successful";
        } else {
            echo "File too large";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

// Example 3: Using pathinfo but not validating extension
function bad_case_3() {
    if (isset($_FILES['attachment'])) {
        $file_name = $_FILES['attachment']['name'];
        $file_tmp = $_FILES['attachment']['tmp_name'];
        $file_info = pathinfo($file_name);
        
        $upload_location = "/var/www/uploads/" . $file_name;
        // ruleid: php-unsafe-file-extension
        if (move_uploaded_file($file_tmp, $upload_location)) {
            echo "File uploaded successfully";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

// Example 4: Checking MIME type but not extension
function bad_case_4() {
    if (isset($_FILES['image'])) {
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime = finfo_file($finfo, $_FILES['image']['tmp_name']);
        finfo_close($finfo);
        
        // Only checking MIME type
        if (strpos($mime, 'image/') === 0) {
            $destination = "/var/www/uploads/" . $_FILES['image']['name'];
            // ruleid: php-unsafe-file-extension
            move_uploaded_file($_FILES['image']['tmp_name'], $destination);
            echo "Image uploaded successfully";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

// Example 5: Renaming file but not checking extension
function bad_case_5() {
    if (isset($_FILES['upload'])) {
        $new_filename = time() . '_' . $_FILES['upload']['name'];
        $upload_dir = '/var/www/html/files/';
        
        // ruleid: php-unsafe-file-extension
        if (move_uploaded_file($_FILES['upload']['tmp_name'], $upload_dir . $new_filename)) {
            echo "File uploaded with new name: $new_filename";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

// Example 6: Using custom function but not validating extension
function bad_case_6() {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $file = $_FILES['document'];
        $target_dir = "uploads/";
        
        // Custom function that doesn't check extension
        function processUpload($file, $dir) {
            $target_file = $dir . basename($file["name"]);
            // ruleid: php-unsafe-file-extension
            if (move_uploaded_file($file["tmp_name"], $target_file)) {
                return true;
            }
            return false;
        }
        
        if (processUpload($file, $target_dir)) {
            echo "The file has been uploaded.";
        } else {
            echo "Sorry, there was an error uploading your file.";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

// Example 7: Multiple file uploads without extension validation
function bad_case_7() {
    if (isset($_FILES['files'])) {
        $files = $_FILES['files'];
        $upload_dir = '/var/www/uploads/';
        
        for ($i = 0; $i < count($files['name']); $i++) {
            $target_file = $upload_dir . basename($files['name'][$i]);
            // ruleid: php-unsafe-file-extension
            move_uploaded_file($files['tmp_name'][$i], $target_file);
        }
        echo "Files uploaded";
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

// Example 8: Ajax file upload without extension validation
function bad_case_8() {
    if (isset($_FILES['ajaxfile'])) {
        $filename = $_FILES['ajaxfile']['name'];
        $tempname = $_FILES['ajaxfile']['tmp_name'];
        $upload_dir = "uploads/";
        
        // ruleid: php-unsafe-file-extension
        if (move_uploaded_file($tempname, $upload_dir . $filename)) {
            echo json_encode(["status" => "success"]);
        } else {
            echo json_encode(["status" => "error"]);
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

// Example 9: Using regex for filename but not extension validation
function bad_case_9() {
    if (isset($_FILES['userfile'])) {
        $filename = $_FILES['userfile']['name'];
        
        // Only checking if filename contains alphanumeric characters
        if (preg_match('/^[a-zA-Z0-9_\-\.]+$/', $filename)) {
            $destination = "/var/www/uploads/" . $filename;
            // ruleid: php-unsafe-file-extension
            move_uploaded_file($_FILES['userfile']['tmp_name'], $destination);
            echo "File uploaded";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

// Example 10: Using base64 decode for file upload without extension validation
function bad_case_10() {
    if (isset($_POST['base64data'])) {
        $base64_string = $_POST['base64data'];
        $filename = $_POST['filename'];
        $output_file = "uploads/" . $filename;
        
        $decoded_data = base64_decode($base64_string);
        // ruleid: php-unsafe-file-extension
        file_put_contents($output_file, $decoded_data);
        echo "File uploaded via base64";
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

// Example 11: Using copy() instead of move_uploaded_file() without extension validation
function bad_case_11() {
    if (isset($_FILES['document'])) {
        $temp_file = $_FILES['document']['tmp_name'];
        $target_file = "uploads/" . $_FILES['document']['name'];
        
        // ruleid: php-unsafe-file-extension
        if (copy($temp_file, $target_file)) {
            unlink($temp_file); // Delete the temporary file
            echo "File uploaded successfully";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

// Example 12: Using file_put_contents with uploaded file without extension validation
function bad_case_12() {
    if (isset($_FILES['upload'])) {
        $content = file_get_contents($_FILES['upload']['tmp_name']);
        $filename = $_FILES['upload']['name'];
        $target_path = "uploads/" . $filename;
        
        // ruleid: php-unsafe-file-extension
        file_put_contents($target_path, $content);
        echo "File saved successfully";
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

// Example 13: Checking file size and type but not extension
function bad_case_13() {
    if (isset($_FILES['image'])) {
        $file = $_FILES['image'];
        $allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
        
        if ($file['size'] <= 2000000 && in_array($file['type'], $allowed_types)) {
            $destination = "gallery/" . $file['name'];
            // ruleid: php-unsafe-file-extension
            move_uploaded_file($file['tmp_name'], $destination);
            echo "Image uploaded successfully";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

// Example 14: Using a database to log uploads but not validating extension
function bad_case_14() {
    if (isset($_FILES['document'])) {
        $file = $_FILES['document'];
        $upload_dir = "documents/";
        $target_file = $upload_dir . basename($file["name"]);
        
        // ruleid: php-unsafe-file-extension
        if (move_uploaded_file($file["tmp_name"], $target_file)) {
            // Log to database (simplified)
            $db = new PDO('mysql:host=localhost;dbname=uploads', 'user', 'password');
            $stmt = $db->prepare("INSERT INTO uploads (filename, upload_date) VALUES (?, NOW())");
            $stmt->execute([$file["name"]]);
            echo "File uploaded and logged";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

// Example 15: Using a custom class but not validating extension
function bad_case_15() {
    class FileUploader {
        private $uploadDir;
        
        public function __construct($dir) {
            $this->uploadDir = $dir;
        }
        
        public function upload($file) {
            $target = $this->uploadDir . basename($file['name']);
            // ruleid: php-unsafe-file-extension
            return move_uploaded_file($file['tmp_name'], $target);
        }
    }
    
    if (isset($_FILES['userfile'])) {
        $uploader = new FileUploader("uploads/");
        if ($uploader->upload($_FILES['userfile'])) {
            echo "File uploaded successfully";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

// TRUE NEGATIVES (Secure Code)

// Example 1: Validating file extension against whitelist
function good_case_1() {
    if (isset($_FILES['userfile'])) {
        $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif'];
        $file_extension = strtolower(pathinfo($_FILES['userfile']['name'], PATHINFO_EXTENSION));
        
        // ok: php-unsafe-file-extension
        if (in_array($file_extension, $allowed_extensions)) {
            $upload_dir = '/var/www/uploads/';
            $upload_file = $upload_dir . basename($_FILES['userfile']['name']);
            move_uploaded_file($_FILES['userfile']['tmp_name'], $upload_file);
            echo "File uploaded successfully";
        } else {
            echo "Invalid file extension";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

// Example 2: Checking both MIME type and extension
function good_case_2() {
    if (isset($_FILES['image'])) {
        $allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
        $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif'];
        
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime_type = finfo_file($finfo, $_FILES['image']['tmp_name']);
        finfo_close($finfo);
        
        $file_extension = strtolower(pathinfo($_FILES['image']['name'], PATHINFO_EXTENSION));
        
        // ok: php-unsafe-file-extension
        if (in_array($mime_type, $allowed_types) && in_array($file_extension, $allowed_extensions)) {
            $destination = "/var/www/uploads/" . $_FILES['image']['name'];
            move_uploaded_file($_FILES['image']['tmp_name'], $destination);
            echo "Image uploaded successfully";
        } else {
            echo "Invalid file type or extension";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

// Example 3: Generating a new filename with validated extension
function good_case_3() {
    if (isset($_FILES['document'])) {
        $allowed_extensions = ['pdf', 'doc', 'docx', 'txt'];
        $file_extension = strtolower(pathinfo($_FILES['document']['name'], PATHINFO_EXTENSION));
        
        // ok: php-unsafe-file-extension
        if (in_array($file_extension, $allowed_extensions)) {
            $new_filename = uniqid() . '.' . $file_extension;
            $destination = "/var/www/documents/" . $new_filename;
            move_uploaded_file($_FILES['document']['tmp_name'], $destination);
            echo "Document uploaded as: $new_filename";
        } else {
            echo "Invalid document type";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

// Example 4: Using a class with extension validation
function good_case_4() {
    class SecureUploader {
        private $allowedExtensions;
        private $uploadDir;
        
        public function __construct($dir, $extensions) {
            $this->uploadDir = $dir;
            $this->allowedExtensions = $extensions;
        }
        
        public function upload($file) {
            $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
            
            // ok: php-unsafe-file-extension
            if (in_array($extension, $this->allowedExtensions)) {
                $target = $this->uploadDir . basename($file['name']);
                return move_uploaded_file($file['tmp_name'], $target);
            }
            return false;
        }
    }
    
    if (isset($_FILES['userfile'])) {
        $uploader = new SecureUploader("uploads/", ['jpg', 'png', 'pdf']);
        if ($uploader->upload($_FILES['userfile'])) {
            echo "File uploaded successfully";
        } else {
            echo "Invalid file type";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

// Example 5: Multiple file uploads with extension validation
function good_case_5() {
    if (isset($_FILES['files'])) {
        $files = $_FILES['files'];
        $upload_dir = '/var/www/uploads/';
        $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif'];
        
        for ($i = 0; $i < count($files['name']); $i++) {
            $file_extension = strtolower(pathinfo($files['name'][$i], PATHINFO_EXTENSION));
            
            // ok: php-unsafe-file-extension
            if (in_array($file_extension, $allowed_extensions)) {
                $target_file = $upload_dir . basename($files['name'][$i]);
                move_uploaded_file($files['tmp_name'][$i], $target_file);
                echo "File {$files['name'][$i]} uploaded<br>";
            } else {
                echo "File {$files['name'][$i]} has invalid extension<br>";
            }
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

// Example 6: Using regex for extension validation
function good_case_6() {
    if (isset($_FILES['upload'])) {
        $filename = $_FILES['upload']['name'];
        $file_extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        
        // ok: php-unsafe-file-extension
        if (preg_match('/^(jpg|jpeg|png|gif)$/', $file_extension)) {
            $destination = "/var/www/images/" . $filename;
            move_uploaded_file($_FILES['upload']['tmp_name'], $destination);
            echo "Image uploaded successfully";
        } else {
            echo "Invalid image format";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

// Example 7: Base64 upload with extension validation
function good_case_7() {
    if (isset($_POST['base64data']) && isset($_POST['filename'])) {
        $base64_string = $_POST['base64data'];
        $filename = $_POST['filename'];
        $file_extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif', 'pdf'];
        
        // ok: php-unsafe-file-extension
        if (in_array($file_extension, $allowed_extensions)) {
            $output_file = "uploads/" . $filename;
            $decoded_data = base64_decode($base64_string);
            file_put_contents($output_file, $decoded_data);
            echo "File uploaded via base64";
        } else {
            echo "Invalid file extension";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

// Example 8: Using a function to validate extension
function good_case_8() {
    function isValidExtension($filename, $allowed_extensions) {
        $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        return in_array($extension, $allowed_extensions);
    }
    
    if (isset($_FILES['document'])) {
        $allowed_extensions = ['pdf', 'doc', 'docx', 'txt', 'xls', 'xlsx'];
        
        // ok: php-unsafe-file-extension
        if (isValidExtension($_FILES['document']['name'], $allowed_extensions)) {
            $destination = "documents/" . $_FILES['document']['name'];
            move_uploaded_file($_FILES['document']['tmp_name'], $destination);
            echo "Document uploaded successfully";
        } else {
            echo "Invalid document type";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

// Example 9: Validating extension and sanitizing filename
function good_case_9() {
    if (isset($_FILES['file'])) {
        $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif', 'pdf'];
        $file_extension = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));
        
        // ok: php-unsafe-file-extension
        if (in_array($file_extension, $allowed_extensions)) {
            // Sanitize filename
            $filename = preg_replace('/[^a-zA-Z0-9_\-\.]/', '_', $_FILES['file']['name']);
            $destination = "uploads/" . $filename;
            move_uploaded_file($_FILES['file']['tmp_name'], $destination);
            echo "File uploaded successfully";
        } else {
            echo "Invalid file type";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

// Example 10: Using a switch statement for extension validation
function good_case_10() {
    if (isset($_FILES['attachment'])) {
        $file_extension = strtolower(pathinfo($_FILES['attachment']['name'], PATHINFO_EXTENSION));
        $valid = false;
        
        switch ($file_extension) {
            case 'pdf':
            case 'doc':
            case 'docx':
            case 'txt':
                $valid = true;
                break;
            default:
                $valid = false;
        }
        
        // ok: php-unsafe-file-extension
        if ($valid) {
            $destination = "documents/" . $_FILES['attachment']['name'];
            move_uploaded_file($_FILES['attachment']['tmp_name'], $destination);
            echo "Document uploaded successfully";
        } else {
            echo "Invalid document type";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

// Example 11: Using a database to check allowed extensions
function good_case_11() {
    if (isset($_FILES['upload'])) {
        $file_extension = strtolower(pathinfo($_FILES['upload']['name'], PATHINFO_EXTENSION));
        
        // Simulating database check for allowed extensions
        $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx'];
        
        // ok: php-unsafe-file-extension
        if (in_array($file_extension, $allowed_extensions)) {
            $destination = "uploads/" . $_FILES['upload']['name'];
            move_uploaded_file($_FILES['upload']['tmp_name'], $destination);
            
            // Log to database (simplified)
            $db = new PDO('mysql:host=localhost;dbname=uploads', 'user', 'password');
            $stmt = $db->prepare("INSERT INTO uploads (filename, extension, upload_date) VALUES (?, ?, NOW())");
            $stmt->execute([$_FILES['upload']['name'], $file_extension]);
            
            echo "File uploaded and logged";
        } else {
            echo "Invalid file type";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

// Example 12: Using file_put_contents with extension validation
function good_case_12() {
    if (isset($_FILES['upload'])) {
        $content = file_get_contents($_FILES['upload']['tmp_name']);
        $filename = $_FILES['upload']['name'];
        $file_extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        $allowed_extensions = ['txt', 'csv', 'json', 'xml'];
        
        // ok: php-unsafe-file-extension
        if (in_array($file_extension, $allowed_extensions)) {
            $target_path = "data/" . $filename;
            file_put_contents($target_path, $content);
            echo "File saved successfully";
        } else {
            echo "Invalid file type";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

// Example 13: Using a configuration file for allowed extensions
function good_case_13() {
    if (isset($_FILES['file'])) {
        // Simulating config file content
        $config = [
            'allowed_extensions' => ['jpg', 'jpeg', 'png', 'gif', 'pdf']
        ];
        
        $file_extension = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));
        
        // ok: php-unsafe-file-extension
        if (in_array($file_extension, $config['allowed_extensions'])) {
            $destination = "uploads/" . $_FILES['file']['name'];
            move_uploaded_file($_FILES['file']['tmp_name'], $destination);
            echo "File uploaded successfully";
        } else {
            echo "Invalid file type";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

// Example 14: Using a more complex validation with extension and MIME type
function good_case_14() {
    if (isset($_FILES['upload'])) {
        $file = $_FILES['upload'];
        $allowed_types = [
            'jpg' => 'image/jpeg',
            'jpeg' => 'image/jpeg',
            'png' => 'image/png',
            'gif' => 'image/gif',
            'pdf' => 'application/pdf'
        ];
        
        $file_extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime_type = finfo_file($finfo, $file['tmp_name']);
        finfo_close($finfo);
        
        // ok: php-unsafe-file-extension
        if (isset($allowed_types[$file_extension]) && $allowed_types[$file_extension] === $mime_type) {
            $destination = "uploads/" . $file['name'];
            move_uploaded_file($file['tmp_name'], $destination);
            echo "File uploaded successfully";
        } else {
            echo "Invalid file type";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

// Example 15: Using a custom class with comprehensive validation
function good_case_15() {
    class FileValidator {
        private $allowedExtensions;
        private $maxSize;
        
        public function __construct($extensions, $size) {
            $this->allowedExtensions = $extensions;
            $this->maxSize = $size;
        }
        
        public function isValid($file) {
            if ($file['size'] > $this->maxSize) {
                return false;
            }
            
            $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
            return in_array($extension, $this->allowedExtensions);
        }
    }
    
    if (isset($_FILES['document'])) {
        $validator = new FileValidator(['pdf', 'doc', 'docx', 'txt'], 5000000);
        
        // ok: php-unsafe-file-extension
        if ($validator->isValid($_FILES['document'])) {
            $destination = "documents/" . $_FILES['document']['name'];
            move_uploaded_file($_FILES['document']['tmp_name'], $destination);
            echo "Document uploaded successfully";
        } else {
            echo "Invalid document";
        }
    }
}
// {/fact}
?>