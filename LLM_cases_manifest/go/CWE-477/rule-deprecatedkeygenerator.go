package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"math/big"
	"os"
)

// True Positive Examples (Vulnerable Code)

// {fact rule=deprecated-method@v1.0 defects=1}
func bad_case_1() {
	// Using deprecated GenerateMultiPrimeKey with insufficient key size
	// ruleid: rule-deprecatedkeygenerator
	privateKey, err := rsa.GenerateMultiPrimeKey(rand.Reader, 3, 1024, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Generated RSA key with %d bits\n", privateKey.N.BitLen())
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
func bad_case_2() {
	// Using deprecated GenerateMultiPrimeKey with default parameters
	// ruleid: rule-deprecatedkeygenerator
	key, err := rsa.GenerateMultiPrimeKey(rand.Reader, 3, 2048, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Generated multi-prime RSA key with size: %d\n", key.N.BitLen())
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
func bad_case_3() {
	// Using deprecated GenerateMultiPrimeKey in a function that creates keys for encryption
	primes := 4
	bits := 4096
	// ruleid: rule-deprecatedkeygenerator
	privateKey, err := rsa.GenerateMultiPrimeKey(rand.Reader, primes, bits, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Generated %d-prime RSA key with %d bits\n", primes, privateKey.N.BitLen())
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
func bad_case_4() {
	// Using deprecated GenerateMultiPrimeKey with variable parameters
	numPrimes := 5
	keySize := 3072
	// ruleid: rule-deprecatedkeygenerator
	key, err := rsa.GenerateMultiPrimeKey(rand.Reader, numPrimes, keySize, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Key generated with %d primes and %d bits\n", numPrimes, key.N.BitLen())
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
func bad_case_5() {
	// Using deprecated GenerateMultiPrimeKey in a conditional block
	useMultiPrime := true
	if useMultiPrime {
		// ruleid: rule-deprecatedkeygenerator
		key, err := rsa.GenerateMultiPrimeKey(rand.Reader, 3, 2048, nil)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Multi-prime key generated: %v\n", key != nil)
	}
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
func bad_case_6() {
	// Using deprecated GenerateMultiPrimeKey with a custom random source
	customRand := rand.Reader
	// ruleid: rule-deprecatedkeygenerator
	key, err := rsa.GenerateMultiPrimeKey(customRand, 3, 2048, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Generated key with custom random source: %v\n", key != nil)
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
func bad_case_7() {
	// Using deprecated GenerateMultiPrimeKey in a loop
	for i := 0; i < 3; i++ {
		// ruleid: rule-deprecatedkeygenerator
		key, err := rsa.GenerateMultiPrimeKey(rand.Reader, 3+i, 2048, nil)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Generated key %d with %d primes\n", i, 3+i)
	}
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
func bad_case_8() {
	// Using deprecated GenerateMultiPrimeKey with a public exponent
	e := big.NewInt(65537)
	// ruleid: rule-deprecatedkeygenerator
	key, err := rsa.GenerateMultiPrimeKey(rand.Reader, 3, 2048, e)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Generated key with public exponent: %v\n", e)
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
func bad_case_9() {
	// Using deprecated GenerateMultiPrimeKey in a function that returns the key
	generateKey := func() (*rsa.PrivateKey, error) {
		// ruleid: rule-deprecatedkeygenerator
		return rsa.GenerateMultiPrimeKey(rand.Reader, 3, 2048, nil)
	}
	key, err := generateKey()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Key generated: %v\n", key != nil)
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
func bad_case_10() {
	// Using deprecated GenerateMultiPrimeKey with error handling
	// ruleid: rule-deprecatedkeygenerator
	key, err := rsa.GenerateMultiPrimeKey(rand.Reader, 3, 2048, nil)
	if err != nil {
		fmt.Printf("Error generating key: %v\n", err)
		return
	}
	fmt.Printf("Successfully generated key with size: %d\n", key.N.BitLen())
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
func bad_case_11() {
	// Using deprecated GenerateMultiPrimeKey with a switch statement
	keyType := "multi"
	switch keyType {
	case "multi":
		// ruleid: rule-deprecatedkeygenerator
		key, err := rsa.GenerateMultiPrimeKey(rand.Reader, 3, 2048, nil)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Generated multi-prime key: %v\n", key != nil)
	default:
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Generated standard key: %v\n", key != nil)
	}
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
func bad_case_12() {
	// Using deprecated GenerateMultiPrimeKey with a defer statement
	defer fmt.Println("Key generation completed")
	// ruleid: rule-deprecatedkeygenerator
	key, err := rsa.GenerateMultiPrimeKey(rand.Reader, 3, 2048, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Generated key: %v\n", key != nil)
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
func bad_case_13() {
	// Using deprecated GenerateMultiPrimeKey with a go routine
	done := make(chan bool)
	go func() {
		// ruleid: rule-deprecatedkeygenerator
		key, err := rsa.GenerateMultiPrimeKey(rand.Reader, 3, 2048, nil)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Generated key in goroutine: %v\n", key != nil)
		done <- true
	}()
	<-done
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
func bad_case_14() {
	// Using deprecated GenerateMultiPrimeKey with command line arguments
	numPrimes := 3
	if len(os.Args) > 1 {
		fmt.Sscanf(os.Args[1], "%d", &numPrimes)
	}
	// ruleid: rule-deprecatedkeygenerator
	key, err := rsa.GenerateMultiPrimeKey(rand.Reader, numPrimes, 2048, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Generated key with %d primes\n", numPrimes)
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
func bad_case_15() {
	// Using deprecated GenerateMultiPrimeKey with a map to store keys
	keys := make(map[string]*rsa.PrivateKey)
	// ruleid: rule-deprecatedkeygenerator
	key, err := rsa.GenerateMultiPrimeKey(rand.Reader, 3, 2048, nil)
	if err != nil {
		log.Fatal(err)
	}
	keys["service1"] = key
	fmt.Printf("Added key to map: %v\n", len(keys))
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=deprecated-method@v1.0 defects=0}
func good_case_1() {
	// Using recommended GenerateKey with sufficient key size
	// ok: rule-deprecatedkeygenerator
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Generated RSA key with %d bits\n", privateKey.N.BitLen())
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
func good_case_2() {
	// Using recommended GenerateKey with larger key size
	// ok: rule-deprecatedkeygenerator
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Generated RSA key with size: %d\n", key.N.BitLen())
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
func good_case_3() {
	// Using recommended GenerateKey in a function that creates keys for encryption
	bits := 3072
	// ok: rule-deprecatedkeygenerator
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Generated RSA key with %d bits\n", privateKey.N.BitLen())
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
func good_case_4() {
	// Using recommended GenerateKey with variable parameters
	keySize := 4096
	// ok: rule-deprecatedkeygenerator
	key, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Key generated with %d bits\n", key.N.BitLen())
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
func good_case_5() {
	// Using recommended GenerateKey in a conditional block
	useStandardKey := true
	if useStandardKey {
		// ok: rule-deprecatedkeygenerator
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Standard key generated: %v\n", key != nil)
	}
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
func good_case_6() {
	// Using recommended GenerateKey with a custom random source
	customRand := rand.Reader
	// ok: rule-deprecatedkeygenerator
	key, err := rsa.GenerateKey(customRand, 2048)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Generated key with custom random source: %v\n", key != nil)
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
func good_case_7() {
	// Using recommended GenerateKey in a loop
	for i := 0; i < 3; i++ {
		// ok: rule-deprecatedkeygenerator
		key, err := rsa.GenerateKey(rand.Reader, 2048+i*1024)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Generated key %d with %d bits\n", i, 2048+i*1024)
	}
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
func good_case_8() {
	// Using recommended GenerateKey with a public exponent
	// ok: rule-deprecatedkeygenerator
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Generated key with public exponent: %v\n", key.PublicKey.E)
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
func good_case_9() {
	// Using recommended GenerateKey in a function that returns the key
	generateKey := func() (*rsa.PrivateKey, error) {
		// ok: rule-deprecatedkeygenerator
		return rsa.GenerateKey(rand.Reader, 2048)
	}
	key, err := generateKey()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Key generated: %v\n", key != nil)
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
func good_case_10() {
	// Using recommended GenerateKey with error handling
	// ok: rule-deprecatedkeygenerator
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("Error generating key: %v\n", err)
		return
	}
	fmt.Printf("Successfully generated key with size: %d\n", key.N.BitLen())
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
func good_case_11() {
	// Using recommended GenerateKey with a switch statement
	keyType := "standard"
	switch keyType {
	case "standard":
		// ok: rule-deprecatedkeygenerator
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Generated standard key: %v\n", key != nil)
	default:
		key, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Generated larger key: %v\n", key != nil)
	}
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
func good_case_12() {
	// Using recommended GenerateKey with a defer statement
	defer fmt.Println("Key generation completed")
	// ok: rule-deprecatedkeygenerator
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Generated key: %v\n", key != nil)
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
func good_case_13() {
	// Using recommended GenerateKey with a go routine
	done := make(chan bool)
	go func() {
		// ok: rule-deprecatedkeygenerator
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Generated key in goroutine: %v\n", key != nil)
		done <- true
	}()
	<-done
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
func good_case_14() {
	// Using recommended GenerateKey with command line arguments
	keySize := 2048
	if len(os.Args) > 1 {
		fmt.Sscanf(os.Args[1], "%d", &keySize)
		if keySize < 2048 {
			keySize = 2048 // Enforce minimum key size
		}
	}
	// ok: rule-deprecatedkeygenerator
	key, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Generated key with %d bits\n", keySize)
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
func good_case_15() {
	// Using recommended GenerateKey with a map to store keys
	keys := make(map[string]*rsa.PrivateKey)
	// ok: rule-deprecatedkeygenerator
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	keys["service1"] = key
	fmt.Printf("Added key to map: %v\n", len(keys))
}
// {/fact}

func main() {
	// This function is just a placeholder and doesn't call any of the test cases
	fmt.Println("RSA Key Generation Test Cases")
}