I'll create 30 examples (15 true positives and 15 true negatives) for the PHP unrestricted file upload vulnerability (CWE-434).

```php
<?php
// PHP Unrestricted File Upload Vulnerability Examples
// {fact rule=unrestricted-file-upload@v1.0 defects=1}
// Rule ID: php-unrestricted-file-upload
// CWE-434

// TRUE POSITIVES (Vulnerable Code)

function bad_case_1() {
    // Simple file upload with no validation except file extension check
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['userfile'])) {
        $uploaddir = '/var/www/uploads/';
        $uploadfile = $uploaddir . basename($_FILES['userfile']['name']);
        
        // Only checking file extension
        $fileType = pathinfo($uploadfile, PATHINFO_EXTENSION);
        if ($fileType == 'jpg' || $fileType == 'png' || $fileType == 'gif') {
            // ruleid: php-unrestricted-file-upload
            if (move_uploaded_file($_FILES['userfile']['tmp_name'], $uploadfile)) {
                echo "File is valid, and was successfully uploaded.\n";
            } else {
                echo "Upload failed.\n";
            }
        } else {
            echo "Invalid file type.\n";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

function bad_case_2() {
    // Checking MIME type from user-provided data which can be spoofed
    if (isset($_FILES['document'])) {
        $allowed_types = array('application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
        
        // Using user-provided MIME type which can be easily spoofed
        if (in_array($_FILES['document']['type'], $allowed_types)) {
            $target_file = "uploads/" . basename($_FILES['document']['name']);
            // ruleid: php-unrestricted-file-upload
            move_uploaded_file($_FILES['document']['tmp_name'], $target_file);
            echo "The file has been uploaded.";
        } else {
            echo "Sorry, only PDF and Word documents are allowed.";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

function bad_case_3() {
    // Using JavaScript-based validation only (which can be bypassed)
    if (isset($_FILES['image'])) {
        // No server-side validation, relying on client-side checks
        $target_dir = "uploads/";
        $target_file = $target_dir . basename($_FILES['image']['name']);
        
        // ruleid: php-unrestricted-file-upload
        if (move_uploaded_file($_FILES['image']['tmp_name'], $target_file)) {
            echo "The file " . basename($_FILES['image']['name']) . " has been uploaded.";
        } else {
            echo "Sorry, there was an error uploading your file.";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

function bad_case_4() {
    // Checking file extension but allowing dangerous extensions
    if (isset($_FILES['upload'])) {
        $filename = $_FILES['upload']['name'];
        $ext = pathinfo($filename, PATHINFO_EXTENSION);
        
        // Allowing potentially dangerous file types
        $allowed = array('jpg', 'png', 'gif', 'php', 'html', 'js');
        
        if (in_array(strtolower($ext), $allowed)) {
            $upload_path = 'uploads/' . $filename;
            // ruleid: php-unrestricted-file-upload
            move_uploaded_file($_FILES['upload']['tmp_name'], $upload_path);
            echo "File uploaded successfully";
        } else {
            echo "Invalid file type";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

function bad_case_5() {
    // Using blacklist approach instead of whitelist
    if (isset($_FILES['attachment'])) {
        $filename = $_FILES['attachment']['name'];
        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        
        // Blacklisting approach is dangerous as it may miss some extensions
        $blacklist = array('exe', 'php', 'phtml', 'php3', 'php4', 'php5');
        
        if (!in_array($ext, $blacklist)) {
            $destination = 'files/' . $filename;
            // ruleid: php-unrestricted-file-upload
            move_uploaded_file($_FILES['attachment']['tmp_name'], $destination);
            echo "File uploaded successfully";
        } else {
            echo "File type not allowed";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

function bad_case_6() {
    // Checking file size but not content
    if (isset($_FILES['document'])) {
        $max_size = 1024 * 1024 * 5; // 5MB
        
        if ($_FILES['document']['size'] <= $max_size) {
            $upload_dir = 'documents/';
            $upload_file = $upload_dir . basename($_FILES['document']['name']);
            
            // ruleid: php-unrestricted-file-upload
            if (move_uploaded_file($_FILES['document']['tmp_name'], $upload_file)) {
                echo "File uploaded successfully.";
            } else {
                echo "Error uploading file.";
            }
        } else {
            echo "File is too large.";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

function bad_case_7() {
    // Checking file extension but with case sensitivity issues
    if (isset($_FILES['avatar'])) {
        $filename = $_FILES['avatar']['name'];
        $extension = pathinfo($filename, PATHINFO_EXTENSION);
        
        // Case-sensitive comparison can be bypassed (e.g., .PHP instead of .php)
        if ($extension == 'jpg' || $extension == 'png' || $extension == 'gif') {
            $target = 'avatars/' . $filename;
            // ruleid: php-unrestricted-file-upload
            move_uploaded_file($_FILES['avatar']['tmp_name'], $target);
            echo "Avatar uploaded.";
        } else {
            echo "Only JPG, PNG, and GIF files are allowed.";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

function bad_case_8() {
    // Checking file extension with string manipulation that can be bypassed
    if (isset($_FILES['file'])) {
        $filename = $_FILES['file']['name'];
        
        // This can be bypassed with filenames like "malicious.php.jpg"
        if (strpos($filename, '.jpg') !== false || strpos($filename, '.png') !== false) {
            $destination = 'gallery/' . $filename;
            // ruleid: php-unrestricted-file-upload
            move_uploaded_file($_FILES['file']['tmp_name'], $destination);
            echo "Image uploaded.";
        } else {
            echo "Only JPG and PNG files are allowed.";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

function bad_case_9() {
    // Using custom file renaming but still allowing dangerous content
    if (isset($_FILES['upload'])) {
        $temp_name = $_FILES['upload']['tmp_name'];
        $original_name = $_FILES['upload']['name'];
        $new_name = uniqid() . '_' . $original_name;
        
        // Just renaming the file doesn't make it safe
        $upload_path = 'user_files/' . $new_name;
        
        // ruleid: php-unrestricted-file-upload
        if (move_uploaded_file($temp_name, $upload_path)) {
            echo "File uploaded with new name: " . $new_name;
        } else {
            echo "Upload failed.";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

function bad_case_10() {
    // Checking file extension with regex but allowing double extensions
    if (isset($_FILES['attachment'])) {
        $filename = $_FILES['attachment']['name'];
        
        // This regex only checks if the filename ends with an allowed extension
        if (preg_match('/\.(jpg|jpeg|png|gif)$/i', $filename)) {
            $destination = 'attachments/' . $filename;
            // ruleid: php-unrestricted-file-upload
            move_uploaded_file($_FILES['attachment']['tmp_name'], $destination);
            echo "File uploaded successfully.";
        } else {
            echo "Invalid file type.";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

function bad_case_11() {
    // Using $_POST data to determine file path
    if (isset($_FILES['file']) && isset($_POST['directory'])) {
        $upload_dir = $_POST['directory']; // User-controlled directory
        
        if (!file_exists($upload_dir)) {
            mkdir($upload_dir, 0777, true);
        }
        
        $target_file = $upload_dir . '/' . basename($_FILES['file']['name']);
        
        // ruleid: php-unrestricted-file-upload
        if (move_uploaded_file($_FILES['file']['tmp_name'], $target_file)) {
            echo "File uploaded to custom directory.";
        } else {
            echo "Upload failed.";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

function bad_case_12() {
    // Using getimagesize() but not checking file content thoroughly
    if (isset($_FILES['profile_pic'])) {
        $temp_file = $_FILES['profile_pic']['tmp_name'];
        
        // getimagesize returns false for non-image files, but doesn't check content safety
        $image_info = getimagesize($temp_file);
        
        if ($image_info !== false) {
            $target = 'profiles/' . basename($_FILES['profile_pic']['name']);
            // ruleid: php-unrestricted-file-upload
            move_uploaded_file($temp_file, $target);
            echo "Profile picture uploaded.";
        } else {
            echo "Invalid image file.";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

function bad_case_13() {
    // Checking file extension after upload
    if (isset($_FILES['document'])) {
        $temp_file = $_FILES['document']['tmp_name'];
        $original_name = $_FILES['document']['name'];
        $target_file = 'docs/' . $original_name;
        
        // ruleid: php-unrestricted-file-upload
        if (move_uploaded_file($temp_file, $target_file)) {
            // Checking after the file is already uploaded
            $extension = pathinfo($target_file, PATHINFO_EXTENSION);
            if (!in_array($extension, ['pdf', 'doc', 'docx'])) {
                unlink($target_file); // Delete if invalid extension
                echo "Invalid file type.";
            } else {
                echo "Document uploaded.";
            }
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

function bad_case_14() {
    // Using finfo but not restricting file type properly
    if (isset($_FILES['file'])) {
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mime_type = $finfo->file($_FILES['file']['tmp_name']);
        
        // Allowing text/plain can be dangerous (could be PHP code)
        $allowed_types = ['image/jpeg', 'image/png', 'text/plain'];
        
        if (in_array($mime_type, $allowed_types)) {
            $target = 'uploads/' . basename($_FILES['file']['name']);
            // ruleid: php-unrestricted-file-upload
            move_uploaded_file($_FILES['file']['tmp_name'], $target);
            echo "File uploaded successfully.";
        } else {
            echo "Invalid file type.";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

function bad_case_15() {
    // Checking file extension but allowing upload to web-accessible directory
    if (isset($_FILES['upload'])) {
        $filename = $_FILES['upload']['name'];
        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        
        if (in_array($ext, ['jpg', 'jpeg', 'png', 'gif'])) {
            // Uploading to web root is dangerous even with image extensions
            $target = $_SERVER['DOCUMENT_ROOT'] . '/images/' . $filename;
            // ruleid: php-unrestricted-file-upload
            move_uploaded_file($_FILES['upload']['tmp_name'], $target);
            echo "Image uploaded to website.";
        } else {
            echo "Only image files are allowed.";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

// TRUE NEGATIVES (Secure Code)

function good_case_1() {
    // Proper file type validation with content verification
    if (isset($_FILES['image'])) {
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mime_type = $finfo->file($_FILES['image']['tmp_name']);
        
        // Whitelist of allowed image types
        $allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
        
        if (in_array($mime_type, $allowed_types)) {
            // Additional verification by trying to create an image from the file
            $image_info = getimagesize($_FILES['image']['tmp_name']);
            if ($image_info !== false) {
                // Generate a new random name to prevent overwriting
                $new_name = uniqid() . '.' . pathinfo($_FILES['image']['name'], PATHINFO_EXTENSION);
                $target = 'uploads/' . $new_name;
                
                // ok: php-unrestricted-file-upload
                move_uploaded_file($_FILES['image']['tmp_name'], $target);
                echo "Image uploaded successfully.";
            } else {
                echo "Invalid image content.";
            }
        } else {
            echo "Only JPG, PNG, and GIF files are allowed.";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

function good_case_2() {
    // Secure PDF upload with content verification
    if (isset($_FILES['document'])) {
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mime_type = $finfo->file($_FILES['document']['tmp_name']);
        
        if ($mime_type === 'application/pdf') {
            // Verify PDF header
            $file = fopen($_FILES['document']['tmp_name'], 'r');
            $header = fread($file, 4);
            fclose($file);
            
            if ($header === '%PDF') {
                $new_name = uniqid() . '.pdf';
                $target = 'documents/' . $new_name;
                
                // ok: php-unrestricted-file-upload
                move_uploaded_file($_FILES['document']['tmp_name'], $target);
                echo "PDF document uploaded successfully.";
            } else {
                echo "Invalid PDF file.";
            }
        } else {
            echo "Only PDF files are allowed.";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

function good_case_3() {
    // Image upload with proper validation and processing
    if (isset($_FILES['avatar'])) {
        // Check MIME type
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $detected_type = $finfo->file($_FILES['avatar']['tmp_name']);
        
        if (in_array($detected_type, ['image/jpeg', 'image/png'])) {
            // Create a new image from the uploaded file based on type
            if ($detected_type === 'image/jpeg') {
                $source_image = imagecreatefromjpeg($_FILES['avatar']['tmp_name']);
            } else {
                $source_image = imagecreatefrompng($_FILES['avatar']['tmp_name']);
            }
            
            if ($source_image !== false) {
                // Process and save the image (resize to prevent malicious oversized images)
                $new_image = imagecreatetruecolor(200, 200);
                imagecopyresampled($new_image, $source_image, 0, 0, 0, 0, 200, 200, 
                                  imagesx($source_image), imagesy($source_image));
                
                $new_filename = 'avatars/' . uniqid() . '.jpg';
                
                // ok: php-unrestricted-file-upload
                imagejpeg($new_image, $new_filename, 90);
                imagedestroy($source_image);
                imagedestroy($new_image);
                
                echo "Avatar processed and saved.";
            } else {
                echo "Invalid image content.";
            }
        } else {
            echo "Only JPEG and PNG files are allowed.";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

function good_case_4() {
    // Secure file upload with comprehensive validation
    if (isset($_FILES['file'])) {
        $temp_file = $_FILES['file']['tmp_name'];
        $original_name = $_FILES['file']['name'];
        
        // Check file size
        $max_size = 1024 * 1024 * 5; // 5MB
        if ($_FILES['file']['size'] > $max_size) {
            echo "File is too large.";
            return;
        }
        
        // Check MIME type
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mime_type = $finfo->file($temp_file);
        
        $allowed_types = ['image/jpeg', 'image/png', 'application/pdf'];
        if (!in_array($mime_type, $allowed_types)) {
            echo "Invalid file type.";
            return;
        }
        
        // Generate a new filename
        $extension = '';
        switch ($mime_type) {
            case 'image/jpeg':
                $extension = 'jpg';
                break;
            case 'image/png':
                $extension = 'png';
                break;
            case 'application/pdf':
                $extension = 'pdf';
                break;
        }
        
        $new_filename = uniqid() . '.' . $extension;
        $target = 'secure_uploads/' . $new_filename;
        
        // ok: php-unrestricted-file-upload
        move_uploaded_file($temp_file, $target);
        echo "File uploaded securely as: " . $new_filename;
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

function good_case_5() {
    // Secure upload with content scanning
    if (isset($_FILES['document'])) {
        $temp_file = $_FILES['document']['tmp_name'];
        
        // Check MIME type
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mime_type = $finfo->file($temp_file);
        
        if ($mime_type === 'application/pdf') {
            // Scan file content for potential threats (simplified example)
            $content = file_get_contents($temp_file);
            $dangerous_patterns = [
                '/<%.*?%>/', // ASP-style code
                '/<script.*?>.*?<\/script>/is', // JavaScript
                '/eval\s*\(/', // JavaScript eval
            ];
            
            $is_safe = true;
            foreach ($dangerous_patterns as $pattern) {
                if (preg_match($pattern, $content)) {
                    $is_safe = false;
                    break;
                }
            }
            
            if ($is_safe) {
                $new_name = uniqid() . '.pdf';
                $target = 'safe_documents/' . $new_name;
                
                // ok: php-unrestricted-file-upload
                move_uploaded_file($temp_file, $target);
                echo "Document scanned and uploaded safely.";
            } else {
                echo "Potentially dangerous content detected.";
            }
        } else {
            echo "Only PDF files are allowed.";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

function good_case_6() {
    // Secure image upload with proper extension handling
    if (isset($_FILES['photo'])) {
        // Check MIME type
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mime_type = $finfo->file($_FILES['photo']['tmp_name']);
        
        $allowed_types = [
            'image/jpeg' => 'jpg',
            'image/png' => 'png',
            'image/gif' => 'gif'
        ];
        
        if (array_key_exists($mime_type, $allowed_types)) {
            // Verify it's actually an image
            $image_info = getimagesize($_FILES['photo']['tmp_name']);
            if ($image_info !== false) {
                // Use the correct extension based on MIME type, not user input
                $extension = $allowed_types[$mime_type];
                $new_filename = uniqid() . '.' . $extension;
                $target = 'photos/' . $new_filename;
                
                // ok: php-unrestricted-file-upload
                move_uploaded_file($_FILES['photo']['tmp_name'], $target);
                echo "Photo uploaded as: " . $new_filename;
            } else {
                echo "Invalid image file.";
            }
        } else {
            echo "Only JPG, PNG, and GIF files are allowed.";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

function good_case_7() {
    // Secure upload with hash verification
    if (isset($_FILES['document'])) {
        $temp_file = $_FILES['document']['tmp_name'];
        
        // Check MIME type
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mime_type = $finfo->file($temp_file);
        
        if ($mime_type === 'application/pdf' || $mime_type === 'application/msword') {
            // Calculate file hash to prevent duplicate uploads
            $file_hash = hash_file('sha256', $temp_file);
            
            // In a real application, you would check this hash against a database
            // of known malicious files or previously uploaded files
            
            // For this example, we'll assume the hash check passed
            $extension = ($mime_type === 'application/pdf') ? 'pdf' : 'doc';
            $new_filename = $file_hash . '.' . $extension;
            $target = 'verified_docs/' . $new_filename;
            
            // ok: php-unrestricted-file-upload
            move_uploaded_file($temp_file, $target);
            echo "Document verified and uploaded with hash: " . $file_hash;
        } else {
            echo "Only PDF and DOC files are allowed.";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

function good_case_8() {
    // Secure upload to non-web-accessible directory
    if (isset($_FILES['confidential'])) {
        // Check MIME type
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mime_type = $finfo->file($_FILES['confidential']['tmp_name']);
        
        $allowed_types = ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
        
        if (in_array($mime_type, $allowed_types)) {
            // Store outside web root
            $upload_dir = dirname($_SERVER['DOCUMENT_ROOT']) . '/private_storage/';
            
            // Ensure directory exists
            if (!file_exists($upload_dir)) {
                mkdir($upload_dir, 0750, true);
            }
            
            $new_filename = uniqid() . '_' . basename($_FILES['confidential']['name']);
            $target = $upload_dir . $new_filename;
            
            // ok: php-unrestricted-file-upload
            move_uploaded_file($_FILES['confidential']['tmp_name'], $target);
            
            // Store reference in database (simplified)
            $file_id = uniqid();
            echo "File stored securely with ID: " . $file_id;
        } else {
            echo "Invalid file type.";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

function good_case_9() {
    // Secure CSV upload with content validation
    if (isset($_FILES['csv_file'])) {
        $temp_file = $_FILES['csv_file']['tmp_name'];
        
        // Check MIME type
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mime_type = $finfo->file($temp_file);
        
        // Check for text/csv or text/plain (CSV files often detected as plain text)
        if ($mime_type === 'text/csv' || $mime_type === 'text/plain') {
            // Verify it's actually a CSV by checking content
            $handle = fopen($temp_file, 'r');
            if ($handle !== false) {
                // Check first few lines for CSV structure
                $is_valid_csv = false;
                for ($i = 0; $i < 3; $i++) {
                    $line = fgets($handle);
                    if ($line === false) break;
                    
                    // Check if line contains commas or semicolons (common CSV delimiters)
                    if (strpos($line, ',') !== false || strpos($line, ';') !== false) {
                        $is_valid_csv = true;
                    }
                }
                fclose($handle);
                
                if ($is_valid_csv) {
                    $new_filename = 'data_' . date('Ymd_His') . '.csv';
                    $target = 'csv_uploads/' . $new_filename;
                    
                    // ok: php-unrestricted-file-upload
                    move_uploaded_file($temp_file, $target);
                    echo "CSV file validated and uploaded.";
                } else {
                    echo "File does not appear to be a valid CSV.";
                }
            } else {
                echo "Could not read the file.";
            }
        } else {
            echo "Only CSV files are allowed.";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

function good_case_10() {
    // Secure upload with file sanitization
    if (isset($_FILES['html_template'])) {
        $temp_file = $_FILES['html_template']['tmp_name'];
        
        // Check MIME type
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mime_type = $finfo->file($temp_file);
        
        if ($mime_type === 'text/html' || $mime_type === 'text/plain') {
            // Read the file content
            $content = file_get_contents($temp_file);
            
            // Sanitize HTML content (remove potentially dangerous elements)
            $allowed_tags = '<p><br><h1><h2><h3><h4><h5><h6><ul><ol><li><strong><em><span><div><table><tr><td><th>';
            $sanitized_content = strip_tags($content, $allowed_tags);
            
            // Remove JavaScript events
            $sanitized_content = preg_replace('/on\w+="[^"]*"/i', '', $sanitized_content);
            $sanitized_content = preg_replace('/on\w+=\'[^\']*\'/i', '', $sanitized_content);
            
            // Save the sanitized content
            $new_filename = 'template_' . uniqid() . '.html';
            $target = 'templates/' . $new_filename;
            
            // ok: php-unrestricted-file-upload
            file_put_contents($target, $sanitized_content);
            echo "HTML template sanitized and saved.";
        } else {
            echo "Only HTML files are allowed.";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

function good_case_11() {
    // Secure upload with file type conversion
    if (isset($_FILES['document'])) {
        $temp_file = $_FILES['document']['tmp_name'];
        
        // Check MIME type
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mime_type = $finfo->file($temp_file);
        
        // Allow various document formats but convert to PDF
        $allowed_types = [
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/pdf'
        ];
        
        if (in_array($mime_type, $allowed_types)) {
            // In a real application, you would use a library to convert the document to PDF
            // For this example, we'll simulate the conversion
            
            // Generate a new filename
            $new_filename = 'document_' . uniqid() . '.pdf';
            $target = 'converted_docs/' . $new_filename;
            
            // Simulate conversion (in reality, you would use a proper conversion library)
            if ($mime_type === 'application/pdf') {
                // Already PDF, just copy
                // ok: php-unrestricted-file-upload
                copy($temp_file, $target);
            } else {
                // In a real application, convert to PDF here
                // For this example, we'll just copy the original
                // ok: php-unrestricted-file-upload
                copy($temp_file, $target);
            }
            
            echo "Document converted to PDF and saved.";
        } else {
            echo "Only Word and PDF documents are allowed.";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

function good_case_12() {
    // Secure upload with virus scanning integration
    if (isset($_FILES['file'])) {
        $temp_file = $_FILES['file']['tmp_name'];
        
        // Check MIME type
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mime_type = $finfo->file($temp_file);
        
        $allowed_types = [
            'application/pdf',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'image/jpeg',
            'image/png'
        ];
        
        if (in_array($mime_type, $allowed_types)) {
            // In a real application, integrate with virus scanning API
            // For this example, we'll simulate the scan
            
            // Simulate virus scan (in reality, you would use a proper AV solution)
            $file_is_safe = simulateVirusScan($temp_file);
            
            if ($file_is_safe) {
                // Generate safe filename based on MIME type
                $extension = '';
                switch ($mime_type) {
                    case 'application/pdf': $extension = 'pdf'; break;
                    case 'application/msword': $extension = 'doc'; break;
                    case 'application/vnd.openxmlformats-officedocument.wordprocessingml.document': $extension = 'docx'; break;
                    case 'image/jpeg': $extension = 'jpg'; break;
                    case 'image/png': $extension = 'png'; break;
                }
                
                $new_filename = 'scanned_' . uniqid() . '.' . $extension;
                $target = 'virus_free/' . $new_filename;
                
                // ok: php-unrestricted-file-upload
                move_uploaded_file($temp_file, $target);
                echo "File scanned and confirmed safe.";
            } else {
                echo "Potential security threat detected in file.";
            }
        } else {
            echo "Invalid file type.";
        }
    }
}
// {/fact}

// Helper function for good_case_12
function simulateVirusScan($file_path) {
    // In a real application, this would connect to an antivirus API
    // For this example, we'll just return true (safe)
    return true;
}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

function good_case_13() {
    // Secure XML upload with schema validation
    if (isset($_FILES['xml_data'])) {
        $temp_file = $_FILES['xml_data']['tmp_name'];
        
        // Check MIME type
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mime_type = $finfo->file($temp_file);
        
        if ($mime_type === 'application/xml' || $mime_type === 'text/xml') {
            // Validate against XML schema
            $is_valid = validateXmlAgainstSchema($temp_file, 'schemas/data_schema.xsd');
            
            if ($is_valid) {
                $new_filename = 'data_' . uniqid() . '.xml';
                $target = 'xml_data/' . $new_filename;
                
                // ok: php-unrestricted-file-upload
                move_uploaded_file($temp_file, $target);
                echo "XML validated and uploaded.";
            } else {
                echo "XML does not conform to required schema.";
            }
        } else {
            echo "Only XML files are allowed.";
        }
    }
}
// {/fact}

// Helper function for good_case_13
function validateXmlAgainstSchema($xml_file, $schema_file) {
    // In a real application, this would validate XML against an XSD schema
    // For this example, we'll simulate validation
    
    // Check if file is well-formed XML
    $xml = simplexml_load_file($xml_file);
    return ($xml !== false);
}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

function good_case_14() {
    // Secure upload with database tracking
    if (isset($_FILES['attachment'])) {
        // Check MIME type
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mime_type = $finfo->file($_FILES['attachment']['tmp_name']);
        
        $allowed_types = [
            'application/pdf' => 'pdf',
            'image/jpeg' => 'jpg',
            'image/png' => 'png',
            'application/msword' => 'doc',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document' => 'docx'
        ];
        
        if (array_key_exists($mime_type, $allowed_types)) {
            // Generate a unique ID for the file
            $file_id = uniqid('file_');
            
            // Use the correct extension based on MIME type
            $extension = $allowed_types[$mime_type];
            $new_filename = $file_id . '.' . $extension;
            
            // Store in a secure location
            $target = 'secure_files/' . $new_filename;
            
            // ok: php-unrestricted-file-upload
            if (move_uploaded_file($_FILES['attachment']['tmp_name'], $target)) {
                // In a real application, you would store file metadata in a database
                $file_size = filesize($target);
                $upload_time = date('Y-m-d H:i:s');
                $original_name = $_FILES['attachment']['name'];
                
                echo "File uploaded with ID: $file_id, Size: $file_size bytes, Type: $mime_type";
            } else {
                echo "Upload failed.";
            }
        } else {
            echo "Invalid file type.";
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

function good_case_15() {
    // Secure upload with strict image processing
    if (isset($_FILES['profile_image'])) {
        // Check MIME type
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mime_type = $finfo->file($_FILES['profile_image']['tmp_name']);
        
        // Only allow image formats
        if ($mime_type === 'image/jpeg' || $mime_type === 'image/png') {
            // Create image resource based on type
            $source_image = null;
            if ($mime_type === 'image/jpeg') {
                $source_image = imagecreatefromjpeg($_FILES['profile_image']['tmp_name']);
            } else {
                $source_image = imagecreatefrompng($_FILES['profile_image']['tmp_name']);
            }
            
            if ($source_image !== false) {
                // Process the image - resize to standard dimensions
                $width = imagesx($source_image);
                $height = imagesy($source_image);
                
                // Calculate new dimensions (maintaining aspect ratio)
                $max_dimension = 500;
                if ($width > $height) {
                    $new_width = $max_dimension;
                    $new_height = floor($height * ($max_dimension / $width));
                } else {
                    $new_height = $max_dimension;
                    $new_width = floor($width * ($max_dimension / $height));
                }
                
                // Create new image with the calculated dimensions
                $new_image = imagecreatetruecolor($new_width, $new_height);
                
                // Handle transparency for PNG
                if ($mime_type === 'image/png') {
                    imagealphablending($new_image, false);
                    imagesavealpha($new_image, true);
                    $transparent = imagecolorallocatealpha($new_image, 255, 255, 255, 127);
                    imagefilledrectangle($new_image, 0, 0, $new_width, $new_height, $transparent);
                }
                
                // Resize the image
                imagecopyresampled($new_image, $source_image, 0, 0, 0, 0, $new_width, $new_height, $width, $height);
                
                // Save the processed image
                $new_filename = 'profile_' . uniqid() . '.jpg';
                $target = 'profile_images/' . $new_filename;
                
                // ok: php-unrestricted-file-upload
                imagejpeg($new_image, $target, 90);
                
                // Clean up
                imagedestroy($source_image);
                imagedestroy($new_image);
                
                echo "Profile image processed and saved.";
            } else {
                echo "Invalid image data.";
            }
        } else {
            echo "Only JPEG and PNG images are allowed.";
        }
    }
}
// {/fact}
?>