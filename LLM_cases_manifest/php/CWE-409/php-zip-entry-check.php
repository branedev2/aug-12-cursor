I'll create 30 examples (15 true positives and 15 true negatives) for the PHP Zip Entry Check vulnerability (CWE-409), which deals with Zip Bomb attacks in PHP.

```php
<?php
/**
 * Test cases for PHP Zip Bomb vulnerability detection
 * Rule ID: php-zip-entry-check
 * CWE: CWE-409
 */
// {fact rule=zip-bomb-attack@v1.0 defects=1}

// True Positives (Vulnerable Code)

function bad_case_1() {
    // Simple extraction without any validation
    $zipFile = $_GET['zipfile'];
    $extractPath = './extracted/';
    
    $zip = new ZipArchive();
    if ($zip->open($zipFile) === TRUE) {
        // ruleid: php-zip-entry-check
        $zip->extractTo($extractPath);
        $zip->close();
        echo 'Extraction complete!';
    } else {
        echo 'Failed to open zip file.';
    }
}
// {/fact}
// {fact rule=zip-bomb-attack@v1.0 defects=1}

function bad_case_2() {
    // Using POST data without validation
    $zipFile = $_POST['archive'];
    $destination = $_POST['destination'];
    
    $zip = new ZipArchive();
    if ($zip->open($zipFile)) {
        // ruleid: php-zip-entry-check
        $zip->extractTo($destination);
        $zip->close();
        echo "Archive extracted successfully";
    }
}
// {/fact}
// {fact rule=zip-bomb-attack@v1.0 defects=1}

function bad_case_3() {
    // Using uploaded file without validation
    if (isset($_FILES['zipfile']) && $_FILES['zipfile']['error'] === UPLOAD_ERR_OK) {
        $tempFile = $_FILES['zipfile']['tmp_name'];
        $extractDir = './uploads/' . uniqid();
        
        $zip = new ZipArchive();
        if ($zip->open($tempFile) === TRUE) {
            // ruleid: php-zip-entry-check
            $zip->extractTo($extractDir);
            $zip->close();
            echo "Extracted to $extractDir";
        }
    }
}
// {/fact}
// {fact rule=zip-bomb-attack@v1.0 defects=1}

function bad_case_4() {
    // Using a loop but still not validating size
    $zipFile = $_GET['file'];
    $extractPath = './data/';
    
    $zip = new ZipArchive();
    if ($zip->open($zipFile) === TRUE) {
        for ($i = 0; $i < $zip->numFiles; $i++) {
            $filename = $zip->getNameIndex($i);
            // ruleid: php-zip-entry-check
            $zip->extractTo($extractPath, $filename);
        }
        $zip->close();
    }
}
// {/fact}
// {fact rule=zip-bomb-attack@v1.0 defects=1}

function bad_case_5() {
    // Using a custom function but still vulnerable
    $zipFile = $_REQUEST['zipfile'];
    $extractPath = './output/';
    
    function processZipFile($file, $path) {
        $zip = new ZipArchive();
        if ($zip->open($file) === TRUE) {
            // ruleid: php-zip-entry-check
            $zip->extractTo($path);
            $zip->close();
            return true;
        }
        return false;
    }
    
    if (processZipFile($zipFile, $extractPath)) {
        echo "Extraction successful";
    }
}
// {/fact}
// {fact rule=zip-bomb-attack@v1.0 defects=1}

function bad_case_6() {
    // Using HTTP headers as input
    $zipFile = $_SERVER['HTTP_X_ZIP_LOCATION'];
    $extractPath = './temp/' . time();
    
    if (!file_exists($extractPath)) {
        mkdir($extractPath, 0777, true);
    }
    
    $zip = new ZipArchive();
    if ($zip->open($zipFile) === TRUE) {
        // ruleid: php-zip-entry-check
        $zip->extractTo($extractPath);
        $zip->close();
    }
}
// {/fact}
// {fact rule=zip-bomb-attack@v1.0 defects=1}

function bad_case_7() {
    // Using cookie data
    $zipFile = $_COOKIE['saved_zip_path'];
    $extractPath = './user_files/';
    
    try {
        $zip = new ZipArchive();
        if ($zip->open($zipFile) === TRUE) {
            // ruleid: php-zip-entry-check
            $zip->extractTo($extractPath);
            $zip->close();
            echo "Extraction completed";
        }
    } catch (Exception $e) {
        echo "Error: " . $e->getMessage();
    }
}
// {/fact}
// {fact rule=zip-bomb-attack@v1.0 defects=1}

function bad_case_8() {
    // Using JSON input
    $jsonData = json_decode(file_get_contents('php://input'), true);
    $zipFile = $jsonData['zipPath'];
    $extractPath = $jsonData['extractPath'];
    
    $zip = new ZipArchive();
    if ($zip->open($zipFile) !== FALSE) {
        // ruleid: php-zip-entry-check
        $zip->extractTo($extractPath);
        $zip->close();
    }
}
// {/fact}
// {fact rule=zip-bomb-attack@v1.0 defects=1}

function bad_case_9() {
    // Checking file extension but not content
    $zipFile = $_GET['archive'];
    $extractPath = './extracted_files/';
    
    if (pathinfo($zipFile, PATHINFO_EXTENSION) === 'zip') {
        $zip = new ZipArchive();
        if ($zip->open($zipFile) === TRUE) {
            // ruleid: php-zip-entry-check
            $zip->extractTo($extractPath);
            $zip->close();
        }
    }
}
// {/fact}
// {fact rule=zip-bomb-attack@v1.0 defects=1}

function bad_case_10() {
    // Using a switch statement but still vulnerable
    $action = $_GET['action'];
    $zipFile = $_GET['file'];
    $extractPath = './output/';
    
    switch ($action) {
        case 'extract':
            $zip = new ZipArchive();
            if ($zip->open($zipFile) === TRUE) {
                // ruleid: php-zip-entry-check
                $zip->extractTo($extractPath);
                $zip->close();
            }
            break;
        case 'list':
            // Some other action
            break;
    }
}
// {/fact}
// {fact rule=zip-bomb-attack@v1.0 defects=1}

function bad_case_11() {
    // Using a class but still vulnerable
    class ZipHandler {
        private $zipFile;
        private $extractPath;
        
        public function __construct($zipFile, $extractPath) {
            $this->zipFile = $zipFile;
            $this->extractPath = $extractPath;
        }
        
        public function extract() {
            $zip = new ZipArchive();
            if ($zip->open($this->zipFile) === TRUE) {
                // ruleid: php-zip-entry-check
                $zip->extractTo($this->extractPath);
                $zip->close();
                return true;
            }
            return false;
        }
    }
    
    $handler = new ZipHandler($_GET['zip'], './extracted/');
    $handler->extract();
}
// {/fact}
// {fact rule=zip-bomb-attack@v1.0 defects=1}

function bad_case_12() {
    // Using array of files but no validation
    $zipFiles = $_POST['zipfiles'];
    $extractPath = './batch_extract/';
    
    foreach ($zipFiles as $zipFile) {
        $zip = new ZipArchive();
        if ($zip->open($zipFile) === TRUE) {
            // ruleid: php-zip-entry-check
            $zip->extractTo($extractPath . basename($zipFile, '.zip'));
            $zip->close();
        }
    }
}
// {/fact}
// {fact rule=zip-bomb-attack@v1.0 defects=1}

function bad_case_13() {
    // Using a ternary operator but still vulnerable
    $zipFile = isset($_GET['zip']) ? $_GET['zip'] : 'default.zip';
    $extractPath = isset($_GET['path']) ? $_GET['path'] : './extracted/';
    
    $zip = new ZipArchive();
    if ($zip->open($zipFile) === TRUE) {
        // ruleid: php-zip-entry-check
        $zip->extractTo($extractPath);
        $zip->close();
    }
}
// {/fact}
// {fact rule=zip-bomb-attack@v1.0 defects=1}

function bad_case_14() {
    // Using error handling but no size validation
    $zipFile = $_REQUEST['archive'];
    $extractPath = './files/';
    
    try {
        $zip = new ZipArchive();
        if ($zip->open($zipFile) !== TRUE) {
            throw new Exception("Cannot open zip file");
        }
        
        // ruleid: php-zip-entry-check
        if (!$zip->extractTo($extractPath)) {
            throw new Exception("Extraction failed");
        }
        
        $zip->close();
        echo "Extraction successful";
    } catch (Exception $e) {
        echo "Error: " . $e->getMessage();
    }
}
// {/fact}
// {fact rule=zip-bomb-attack@v1.0 defects=1}

function bad_case_15() {
    // Using a complex condition but still vulnerable
    $zipFile = $_GET['file'];
    $extractPath = $_GET['path'];
    $allowExtract = $_GET['allow'] === 'true';
    
    if (file_exists($zipFile) && is_readable($zipFile) && $allowExtract) {
        $zip = new ZipArchive();
        if ($zip->open($zipFile) === TRUE) {
            // ruleid: php-zip-entry-check
            $zip->extractTo($extractPath);
            $zip->close();
        }
    }
}
// {/fact}
// {fact rule=zip-bomb-attack@v1.0 defects=0}

// True Negatives (Safe Code)

function good_case_1() {
    // Checking total uncompressed size before extraction
    $zipFile = $_GET['zipfile'];
    $extractPath = './extracted/';
    $maxSize = 1024 * 1024 * 1024; // 1GB limit
    
    $zip = new ZipArchive();
    if ($zip->open($zipFile) === TRUE) {
        $totalSize = 0;
        for ($i = 0; $i < $zip->numFiles; $i++) {
            $stat = $zip->statIndex($i);
            $totalSize += $stat['size'];
            
            // Check for suspicious compression ratio
            if ($stat['size'] > 0 && $stat['comp_size'] > 0) {
                $ratio = $stat['size'] / $stat['comp_size'];
                if ($ratio > 1000) {
                    echo "Suspicious compression ratio detected!";
                    $zip->close();
                    return;
                }
            }
        }
        
        if ($totalSize > $maxSize) {
            echo "Extracted size would exceed limit!";
            $zip->close();
            return;
        }
        
        // ok: php-zip-entry-check
        $zip->extractTo($extractPath);
        $zip->close();
        echo 'Extraction complete!';
    }
}
// {/fact}
// {fact rule=zip-bomb-attack@v1.0 defects=0}

function good_case_2() {
    // Using POST data with validation
    $zipFile = $_POST['archive'];
    $destination = $_POST['destination'];
    $maxSize = 500 * 1024 * 1024; // 500MB
    
    $zip = new ZipArchive();
    if ($zip->open($zipFile)) {
        // Check total size
        $totalSize = 0;
        for ($i = 0; $i < $zip->numFiles; $i++) {
            $stat = $zip->statIndex($i);
            $totalSize += $stat['size'];
        }
        
        if ($totalSize <= $maxSize) {
            // ok: php-zip-entry-check
            $zip->extractTo($destination);
            $zip->close();
            echo "Archive extracted successfully";
        } else {
            echo "Archive too large to extract";
            $zip->close();
        }
    }
}
// {/fact}
// {fact rule=zip-bomb-attack@v1.0 defects=0}

function good_case_3() {
    // Using uploaded file with validation
    if (isset($_FILES['zipfile']) && $_FILES['zipfile']['error'] === UPLOAD_ERR_OK) {
        $tempFile = $_FILES['zipfile']['tmp_name'];
        $extractDir = './uploads/' . uniqid();
        $maxSize = 100 * 1024 * 1024; // 100MB
        $maxRatio = 1000;
        
        $zip = new ZipArchive();
        if ($zip->open($tempFile) === TRUE) {
            $totalSize = 0;
            $isSafe = true;
            
            for ($i = 0; $i < $zip->numFiles; $i++) {
                $stat = $zip->statIndex($i);
                $totalSize += $stat['size'];
                
                // Check compression ratio
                if ($stat['comp_size'] > 0) {
                    $ratio = $stat['size'] / $stat['comp_size'];
                    if ($ratio > $maxRatio) {
                        $isSafe = false;
                        break;
                    }
                }
            }
            
            if ($isSafe && $totalSize <= $maxSize) {
                // ok: php-zip-entry-check
                $zip->extractTo($extractDir);
                echo "Extracted to $extractDir";
            } else {
                echo "Potentially malicious zip file detected";
            }
            $zip->close();
        }
    }
}
// {/fact}
// {fact rule=zip-bomb-attack@v1.0 defects=0}

function good_case_4() {
    // Using a loop with validation
    $zipFile = $_GET['file'];
    $extractPath = './data/';
    $maxFileSize = 50 * 1024 * 1024; // 50MB per file
    
    $zip = new ZipArchive();
    if ($zip->open($zipFile) === TRUE) {
        for ($i = 0; $i < $zip->numFiles; $i++) {
            $filename = $zip->getNameIndex($i);
            $stat = $zip->statIndex($i);
            
            if ($stat['size'] <= $maxFileSize) {
                // ok: php-zip-entry-check
                $zip->extractTo($extractPath, $filename);
            } else {
                echo "File $filename is too large to extract";
            }
        }
        $zip->close();
    }
}
// {/fact}
// {fact rule=zip-bomb-attack@v1.0 defects=0}

function good_case_5() {
    // Using a custom function with validation
    $zipFile = $_REQUEST['zipfile'];
    $extractPath = './output/';
    
    function safeExtractZip($file, $path, $maxTotalSize = 1073741824) {
        $zip = new ZipArchive();
        if ($zip->open($file) === TRUE) {
            $totalSize = 0;
            
            // Check total size
            for ($i = 0; $i < $zip->numFiles; $i++) {
                $stat = $zip->statIndex($i);
                $totalSize += $stat['size'];
                
                // Check for suspicious files
                if ($stat['comp_size'] > 0 && ($stat['size'] / $stat['comp_size']) > 1000) {
                    $zip->close();
                    return false;
                }
            }
            
            if ($totalSize <= $maxTotalSize) {
                // ok: php-zip-entry-check
                $zip->extractTo($path);
                $zip->close();
                return true;
            }
            $zip->close();
        }
        return false;
    }
    
    if (safeExtractZip($zipFile, $extractPath)) {
        echo "Extraction successful";
    } else {
        echo "Extraction failed - size limit exceeded or suspicious content";
    }
}
// {/fact}
// {fact rule=zip-bomb-attack@v1.0 defects=0}

function good_case_6() {
    // Using HTTP headers as input with validation
    $zipFile = $_SERVER['HTTP_X_ZIP_LOCATION'];
    $extractPath = './temp/' . time();
    $maxSize = 200 * 1024 * 1024; // 200MB
    
    if (!file_exists($extractPath)) {
        mkdir($extractPath, 0777, true);
    }
    
    $zip = new ZipArchive();
    if ($zip->open($zipFile) === TRUE) {
        // Calculate total size
        $totalSize = 0;
        for ($i = 0; $i < $zip->numFiles; $i++) {
            $stat = $zip->statIndex($i);
            $totalSize += $stat['size'];
        }
        
        if ($totalSize <= $maxSize) {
            // ok: php-zip-entry-check
            $zip->extractTo($extractPath);
        } else {
            echo "Archive exceeds maximum allowed size";
        }
        $zip->close();
    }
}
// {/fact}
// {fact rule=zip-bomb-attack@v1.0 defects=0}

function good_case_7() {
    // Using cookie data with validation
    $zipFile = $_COOKIE['saved_zip_path'];
    $extractPath = './user_files/';
    $maxTotalSize = 150 * 1024 * 1024; // 150MB
    
    try {
        $zip = new ZipArchive();
        if ($zip->open($zipFile) === TRUE) {
            // Check size and ratio
            $totalSize = 0;
            $suspiciousFile = false;
            
            for ($i = 0; $i < $zip->numFiles; $i++) {
                $stat = $zip->statIndex($i);
                $totalSize += $stat['size'];
                
                // Check compression ratio
                if ($stat['comp_size'] > 0 && ($stat['size'] / $stat['comp_size']) > 1000) {
                    $suspiciousFile = true;
                    break;
                }
            }
            
            if (!$suspiciousFile && $totalSize <= $maxTotalSize) {
                // ok: php-zip-entry-check
                $zip->extractTo($extractPath);
                echo "Extraction completed";
            } else {
                echo "Suspicious zip file detected";
            }
            $zip->close();
        }
    } catch (Exception $e) {
        echo "Error: " . $e->getMessage();
    }
}
// {/fact}
// {fact rule=zip-bomb-attack@v1.0 defects=0}

function good_case_8() {
    // Using JSON input with validation
    $jsonData = json_decode(file_get_contents('php://input'), true);
    $zipFile = $jsonData['zipPath'];
    $extractPath = $jsonData['extractPath'];
    $maxSize = 500 * 1024 * 1024; // 500MB
    
    $zip = new ZipArchive();
    if ($zip->open($zipFile) !== FALSE) {
        $totalUncompressedSize = 0;
        
        // Calculate total uncompressed size
        for ($i = 0; $i < $zip->numFiles; $i++) {
            $stat = $zip->statIndex($i);
            $totalUncompressedSize += $stat['size'];
            
            // Check for suspicious compression ratio
            if ($stat['comp_size'] > 0) {
                $ratio = $stat['size'] / $stat['comp_size'];
                if ($ratio > 1000) {
                    echo "Suspicious compression ratio detected";
                    $zip->close();
                    return;
                }
            }
        }
        
        if ($totalUncompressedSize <= $maxSize) {
            // ok: php-zip-entry-check
            $zip->extractTo($extractPath);
        } else {
            echo "Zip file too large to extract safely";
        }
        $zip->close();
    }
}
// {/fact}
// {fact rule=zip-bomb-attack@v1.0 defects=0}

function good_case_9() {
    // Checking file extension and content
    $zipFile = $_GET['archive'];
    $extractPath = './extracted_files/';
    $maxSize = 250 * 1024 * 1024; // 250MB
    
    if (pathinfo($zipFile, PATHINFO_EXTENSION) === 'zip') {
        $zip = new ZipArchive();
        if ($zip->open($zipFile) === TRUE) {
            // Validate size
            $totalSize = 0;
            for ($i = 0; $i < $zip->numFiles; $i++) {
                $stat = $zip->statIndex($i);
                $totalSize += $stat['size'];
            }
            
            if ($totalSize <= $maxSize) {
                // ok: php-zip-entry-check
                $zip->extractTo($extractPath);
            } else {
                echo "Archive too large to extract safely";
            }
            $zip->close();
        }
    }
}
// {/fact}
// {fact rule=zip-bomb-attack@v1.0 defects=0}

function good_case_10() {
    // Using a switch statement with validation
    $action = $_GET['action'];
    $zipFile = $_GET['file'];
    $extractPath = './output/';
    $maxSize = 100 * 1024 * 1024; // 100MB
    
    switch ($action) {
        case 'extract':
            $zip = new ZipArchive();
            if ($zip->open($zipFile) === TRUE) {
                // Calculate total size
                $totalSize = 0;
                for ($i = 0; $i < $zip->numFiles; $i++) {
                    $stat = $zip->statIndex($i);
                    $totalSize += $stat['size'];
                }
                
                if ($totalSize <= $maxSize) {
                    // ok: php-zip-entry-check
                    $zip->extractTo($extractPath);
                } else {
                    echo "Archive exceeds size limit";
                }
                $zip->close();
            }
            break;
        case 'list':
            // Some other action
            break;
    }
}
// {/fact}
// {fact rule=zip-bomb-attack@v1.0 defects=0}

function good_case_11() {
    // Using a class with proper validation
    class SafeZipHandler {
        private $zipFile;
        private $extractPath;
        private $maxSize;
        private $maxRatio;
        
        public function __construct($zipFile, $extractPath, $maxSize = 1073741824, $maxRatio = 1000) {
            $this->zipFile = $zipFile;
            $this->extractPath = $extractPath;
            $this->maxSize = $maxSize;
            $this->maxRatio = $maxRatio;
        }
        
        public function extract() {
            $zip = new ZipArchive();
            if ($zip->open($this->zipFile) === TRUE) {
                // Validate size and ratio
                $totalSize = 0;
                for ($i = 0; $i < $zip->numFiles; $i++) {
                    $stat = $zip->statIndex($i);
                    $totalSize += $stat['size'];
                    
                    if ($stat['comp_size'] > 0) {
                        $ratio = $stat['size'] / $stat['comp_size'];
                        if ($ratio > $this->maxRatio) {
                            $zip->close();
                            return false;
                        }
                    }
                }
                
                if ($totalSize <= $this->maxSize) {
                    // ok: php-zip-entry-check
                    $zip->extractTo($this->extractPath);
                    $zip->close();
                    return true;
                }
                $zip->close();
            }
            return false;
        }
    }
    
    $handler = new SafeZipHandler($_GET['zip'], './extracted/');
    if ($handler->extract()) {
        echo "Extraction successful";
    } else {
        echo "Extraction failed - size limit exceeded or suspicious content";
    }
}
// {/fact}
// {fact rule=zip-bomb-attack@v1.0 defects=0}

function good_case_12() {
    // Using array of files with validation
    $zipFiles = $_POST['zipfiles'];
    $extractPath = './batch_extract/';
    $maxSizePerFile = 50 * 1024 * 1024; // 50MB per file
    
    foreach ($zipFiles as $zipFile) {
        $zip = new ZipArchive();
        if ($zip->open($zipFile) === TRUE) {
            // Check size
            $totalSize = 0;
            $isSafe = true;
            
            for ($i = 0; $i < $zip->numFiles; $i++) {
                $stat = $zip->statIndex($i);
                $totalSize += $stat['size'];
                
                // Check for suspicious compression ratio
                if ($stat['comp_size'] > 0 && ($stat['size'] / $stat['comp_size']) > 1000) {
                    $isSafe = false;
                    break;
                }
            }
            
            if ($isSafe && $totalSize <= $maxSizePerFile) {
                // ok: php-zip-entry-check
                $zip->extractTo($extractPath . basename($zipFile, '.zip'));
            } else {
                echo "Skipping " . basename($zipFile) . " - suspicious or too large";
            }
            $zip->close();
        }
    }
}
// {/fact}
// {fact rule=zip-bomb-attack@v1.0 defects=0}

function good_case_13() {
    // Using a ternary operator with validation
    $zipFile = isset($_GET['zip']) ? $_GET['zip'] : 'default.zip';
    $extractPath = isset($_GET['path']) ? $_GET['path'] : './extracted/';
    $maxSize = 300 * 1024 * 1024; // 300MB
    
    $zip = new ZipArchive();
    if ($zip->open($zipFile) === TRUE) {
        // Calculate total size
        $totalSize = 0;
        for ($i = 0; $i < $zip->numFiles; $i++) {
            $stat = $zip->statIndex($i);
            $totalSize += $stat['size'];
        }
        
        if ($totalSize <= $maxSize) {
            // ok: php-zip-entry-check
            $zip->extractTo($extractPath);
        } else {
            echo "Archive too large to extract safely";
        }
        $zip->close();
    }
}
// {/fact}
// {fact rule=zip-bomb-attack@v1.0 defects=0}

function good_case_14() {
    // Using error handling with proper validation
    $zipFile = $_REQUEST['archive'];
    $extractPath = './files/';
    $maxSize = 200 * 1024 * 1024; // 200MB
    $maxRatio = 1000;
    
    try {
        $zip = new ZipArchive();
        if ($zip->open($zipFile) !== TRUE) {
            throw new Exception("Cannot open zip file");
        }
        
        // Validate content
        $totalSize = 0;
        for ($i = 0; $i < $zip->numFiles; $i++) {
            $stat = $zip->statIndex($i);
            $totalSize += $stat['size'];
            
            // Check compression ratio
            if ($stat['comp_size'] > 0) {
                $ratio = $stat['size'] / $stat['comp_size'];
                if ($ratio > $maxRatio) {
                    throw new Exception("Suspicious compression ratio detected");
                }
            }
        }
        
        if ($totalSize > $maxSize) {
            throw new Exception("Archive exceeds size limit");
        }
        
        // ok: php-zip-entry-check
        if (!$zip->extractTo($extractPath)) {
            throw new Exception("Extraction failed");
        }
        
        $zip->close();
        echo "Extraction successful";
    } catch (Exception $e) {
        echo "Error: " . $e->getMessage();
        if (isset($zip) && is_object($zip)) {
            $zip->close();
        }
    }
}
// {/fact}
// {fact rule=zip-bomb-attack@v1.0 defects=0}

function good_case_15() {
    // Using a complex condition with validation
    $zipFile = $_GET['file'];
    $extractPath = $_GET['path'];
    $allowExtract = $_GET['allow'] === 'true';
    $maxSize = 150 * 1024 * 1024; // 150MB
    
    if (file_exists($zipFile) && is_readable($zipFile) && $allowExtract) {
        $zip = new ZipArchive();
        if ($zip->open($zipFile) === TRUE) {
            // Check size
            $totalSize = 0;
            for ($i = 0; $i < $zip->numFiles; $i++) {
                $stat = $zip->statIndex($i);
                $totalSize += $stat['size'];
                
                // Check for suspicious files
                if ($stat['comp_size'] > 0 && ($stat['size'] / $stat['comp_size']) > 1000) {
                    echo "Suspicious compression ratio detected";
                    $zip->close();
                    return;
                }
            }
            
            if ($totalSize <= $maxSize) {
                // ok: php-zip-entry-check
                $zip->extractTo($extractPath);
            } else {
                echo "Archive too large to extract safely";
            }
            $zip->close();
        }
    }
}
// {/fact}
?>