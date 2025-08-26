<?php
// {fact rule=arithmetic-overflow@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

// Example 1: Simple integer overflow in addition
function bad_case_1() {
    $maxInt = PHP_INT_MAX;
    $result = $maxInt + 1; // This will overflow
    // ruleid: php-integer-overflow
    echo "Result: " . $result;
}
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=1}

// Example 2: Integer overflow in multiplication
function bad_case_2() {
    $largeNumber = PHP_INT_MAX / 2;
    // ruleid: php-integer-overflow
    $result = $largeNumber * 3; // Will overflow
    echo "Multiplication result: " . $result;
}
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=1}

// Example 3: Integer overflow with user input
function bad_case_3() {
    $userInput = $_GET['value'];
    $multiplier = 1000000000;
    // ruleid: php-integer-overflow
    $result = $userInput * $multiplier; // Can overflow with large input
    echo "User calculation: " . $result;
}
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=1}

// Example 4: Integer overflow in loop counter
function bad_case_4() {
    $counter = PHP_INT_MAX - 5;
    for ($i = 0; $i < 10; $i++) {
        // ruleid: php-integer-overflow
        $counter++; // Will overflow after 5 iterations
        echo "Counter: " . $counter . "<br>";
    }
}
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=1}

// Example 5: Integer overflow in array index calculation
function bad_case_5() {
    $array = array_fill(0, 100, 'value');
    $userInput = $_POST['index'];
    // ruleid: php-integer-overflow
    $index = $userInput * 1000000000; // Can overflow
    echo "Value at calculated index: " . $array[$index % 100];
}
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=1}

// Example 6: Integer overflow in bit shifting
function bad_case_6() {
    $baseValue = 1;
    $shiftAmount = 63; // On 64-bit systems, this is dangerous
    // ruleid: php-integer-overflow
    $result = $baseValue << $shiftAmount; // Will overflow
    echo "Shifted result: " . $result;
}
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=1}

// Example 7: Integer overflow in factorial calculation
function bad_case_7() {
    $n = $_GET['factorial'];
    $result = 1;
    for ($i = 2; $i <= $n; $i++) {
        // ruleid: php-integer-overflow
        $result *= $i; // Will overflow for large factorials
    }
    echo "Factorial result: " . $result;
}
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=1}

// Example 8: Integer overflow in exponential calculation
function bad_case_8() {
    $base = $_POST['base'];
    $exponent = $_POST['exponent'];
    $result = 1;
    for ($i = 0; $i < $exponent; $i++) {
        // ruleid: php-integer-overflow
        $result *= $base; // Can overflow with large base/exponent
    }
    echo "Power result: " . $result;
}
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=1}

// Example 9: Integer overflow in timestamp calculation
function bad_case_9() {
    $currentTimestamp = time();
    $daysToAdd = $_GET['days'];
    // ruleid: php-integer-overflow
    $futureTimestamp = $currentTimestamp + ($daysToAdd * 86400); // Can overflow
    echo "Future date: " . date('Y-m-d', $futureTimestamp);
}
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=1}

// Example 10: Integer overflow in percentage calculation
function bad_case_10() {
    $value = $_POST['value'];
    $percentage = $_POST['percentage'];
    // ruleid: php-integer-overflow
    $result = $value * $percentage / 100; // Can overflow with large values
    echo "Percentage result: " . $result;
}
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=1}

// Example 11: Integer overflow in recursive function
function bad_case_11() {
    function fibonacci($n) {
        if ($n <= 1) return $n;
        // ruleid: php-integer-overflow
        return fibonacci($n - 1) + fibonacci($n - 2); // Will overflow for large n
    }
    
    $userInput = $_GET['fib'];
    echo "Fibonacci result: " . fibonacci($userInput);
}
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=1}

// Example 12: Integer overflow in compound assignment
function bad_case_12() {
    $value = PHP_INT_MAX - 5;
    $increment = $_POST['increment'];
    // ruleid: php-integer-overflow
    $value += $increment; // Will overflow if increment > 5
    echo "New value: " . $value;
}
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=1}

// Example 13: Integer overflow in database ID calculation
function bad_case_13() {
    $baseId = $_GET['id'];
    $multiplier = 1000000;
    // ruleid: php-integer-overflow
    $calculatedId = $baseId * $multiplier; // Can overflow
    $query = "SELECT * FROM users WHERE id = " . $calculatedId;
    // Execute query (simplified for example)
    echo "Query: " . $query;
}
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=1}

// Example 14: Integer overflow in memory allocation calculation
function bad_case_14() {
    $itemSize = 8; // bytes
    $itemCount = $_POST['count'];
    // ruleid: php-integer-overflow
    $totalSize = $itemSize * $itemCount; // Can overflow
    $buffer = str_repeat('A', $totalSize); // Potential memory issues
    echo "Buffer size: " . strlen($buffer);
}
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=1}

// Example 15: Integer overflow in hash calculation
function bad_case_15() {
    $userId = $_GET['user_id'];
    $timestamp = time();
    // ruleid: php-integer-overflow
    $hashInput = $userId * $timestamp; // Can overflow with large user IDs
    $hash = md5($hashInput);
    echo "Generated hash: " . $hash;
}
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=0}

// True Negative Examples (Safe Code)

// Example 1: Using GMP for large integer operations
function good_case_1() {
    // ok: php-integer-overflow
    $maxInt = gmp_init(PHP_INT_MAX);
    $result = gmp_add($maxInt, 1); // No overflow with GMP
    echo "Result: " . gmp_strval($result);
}
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=0}

// Example 2: Using BCMath for large integer operations
function good_case_2() {
    $largeNumber = PHP_INT_MAX / 2;
    // ok: php-integer-overflow
    $result = bcmul($largeNumber, "3"); // No overflow with BCMath
    echo "Multiplication result: " . $result;
}
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=0}

// Example 3: Checking for potential overflow before operation
function good_case_3() {
    $userInput = intval($_GET['value']);
    $multiplier = 1000000000;
    
    // ok: php-integer-overflow
    if ($userInput > 0 && $userInput > PHP_INT_MAX / $multiplier) {
        echo "Error: Potential integer overflow detected";
    } else {
        $result = $userInput * $multiplier;
        echo "User calculation: " . $result;
    }
}
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=0}

// Example 4: Safe loop counter with bounds checking
function good_case_4() {
    $counter = PHP_INT_MAX - 5;
    for ($i = 0; $i < 10; $i++) {
        // ok: php-integer-overflow
        if ($counter == PHP_INT_MAX) {
            echo "Maximum value reached<br>";
            break;
        }
        $counter++;
        echo "Counter: " . $counter . "<br>";
    }
}
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=0}

// Example 5: Safe array index calculation with validation
function good_case_5() {
    $array = array_fill(0, 100, 'value');
    $userInput = intval($_POST['index']);
    
    // ok: php-integer-overflow
    if ($userInput > PHP_INT_MAX / 1000000000) {
        $index = 0; // Default safe value
    } else {
        $index = $userInput * 1000000000;
    }
    
    echo "Value at calculated index: " . $array[$index % 100];
}
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=0}

// Example 6: Safe bit shifting with bounds checking
function good_case_6() {
    $baseValue = 1;
    $shiftAmount = 63; // On 64-bit systems, this is dangerous
    
    // ok: php-integer-overflow
    if ($shiftAmount >= PHP_INT_SIZE * 8 - 1) {
        echo "Shift amount too large, would cause overflow";
    } else {
        $result = $baseValue << $shiftAmount;
        echo "Shifted result: " . $result;
    }
}
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=0}

// Example 7: Safe factorial calculation with overflow detection
function good_case_7() {
    $n = intval($_GET['factorial']);
    $result = 1;
    
    // ok: php-integer-overflow
    for ($i = 2; $i <= $n; $i++) {
        if ($result > PHP_INT_MAX / $i) {
            echo "Factorial too large, switching to BCMath<br>";
            $bcResult = bcfact($n);
            echo "Factorial result: " . $bcResult;
            return;
        }
        $result *= $i;
    }
    
    echo "Factorial result: " . $result;
}
// {/fact}

// Helper function for BCMath factorial
function bcfact($n) {
    $result = "1";
    for ($i = 2; $i <= $n; $i++) {
        $result = bcmul($result, $i);
    }
    return $result;
}
// {fact rule=arithmetic-overflow@v1.0 defects=0}

// Example 8: Safe exponential calculation with BCMath
function good_case_8() {
    $base = $_POST['base'];
    $exponent = $_POST['exponent'];
    
    // ok: php-integer-overflow
    $result = bcpow($base, $exponent);
    echo "Power result: " . $result;
}
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=0}

// Example 9: Safe timestamp calculation with bounds checking
function good_case_9() {
    $currentTimestamp = time();
    $daysToAdd = intval($_GET['days']);
    
    // ok: php-integer-overflow
    if ($daysToAdd > (PHP_INT_MAX - $currentTimestamp) / 86400) {
        echo "Error: Date calculation would overflow";
    } else {
        $futureTimestamp = $currentTimestamp + ($daysToAdd * 86400);
        echo "Future date: " . date('Y-m-d', $futureTimestamp);
    }
}
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=0}

// Example 10: Safe percentage calculation with type conversion
function good_case_10() {
    $value = floatval($_POST['value']);
    $percentage = floatval($_POST['percentage']);
    
    // ok: php-integer-overflow
    $result = $value * $percentage / 100; // Using float prevents integer overflow
    echo "Percentage result: " . $result;
}
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=0}

// Example 11: Safe recursive function with memoization to prevent overflow
function good_case_11() {
    function safeFibonacci($n, &$memo = []) {
        if ($n <= 1) return $n;
        if (isset($memo[$n])) return $memo[$n];
        
        // ok: php-integer-overflow
        if ($n > 1476) { // Fibonacci(1476) is near PHP_FLOAT_MAX
            return "Value too large to calculate";
        }
        
        $memo[$n] = safeFibonacci($n - 1, $memo) + safeFibonacci($n - 2, $memo);
        return $memo[$n];
    }
    
    $userInput = intval($_GET['fib']);
    echo "Fibonacci result: " . safeFibonacci($userInput);
}
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=0}

// Example 12: Safe compound assignment with overflow check
function good_case_12() {
    $value = PHP_INT_MAX - 5;
    $increment = intval($_POST['increment']);
    
    // ok: php-integer-overflow
    if ($increment > 0 && $value > PHP_INT_MAX - $increment) {
        echo "Error: Operation would cause overflow";
    } else {
        $value += $increment;
        echo "New value: " . $value;
    }
}
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=0}

// Example 13: Safe database ID calculation with string-based IDs
function good_case_13() {
    $baseId = $_GET['id'];
    
    // ok: php-integer-overflow
    $calculatedId = $baseId; // Use the ID directly or hash it
    $query = "SELECT * FROM users WHERE id = '" . $calculatedId . "'";
    // Execute query (simplified for example)
    echo "Query: " . $query;
}
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=0}

// Example 14: Safe memory allocation with size validation
function good_case_14() {
    $itemSize = 8; // bytes
    $itemCount = intval($_POST['count']);
    $maxAllocation = 1024 * 1024; // 1MB limit
    
    // ok: php-integer-overflow
    if ($itemCount < 0 || $itemSize * $itemCount > $maxAllocation) {
        echo "Error: Requested allocation size exceeds limits";
    } else {
        $totalSize = $itemSize * $itemCount;
        $buffer = str_repeat('A', $totalSize);
        echo "Buffer size: " . strlen($buffer);
    }
}
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=0}

// Example 15: Safe hash calculation using string concatenation
function good_case_15() {
    $userId = $_GET['user_id'];
    $timestamp = time();
    
    // ok: php-integer-overflow
    $hashInput = $userId . "_" . $timestamp; // String concatenation avoids overflow
    $hash = md5($hashInput);
    echo "Generated hash: " . $hash;
}
// {/fact}

?>