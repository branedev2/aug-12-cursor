package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

// True Positives (Vulnerable Cases)

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_1() {
	// Using 1024 bits for RSA key generation
	// ruleid: rule-weakkeystrength-updatedMIT
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		log.Fatal(err)
	}
	
	// Save the private key to a file
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyBytes,
		},
	)
	ioutil.WriteFile("private_key.pem", privateKeyPEM, 0600)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_2() {
	// Using 512 bits for RSA key generation - even weaker
	// ruleid: rule-weakkeystrength-updatedMIT
	privateKey, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		log.Fatal(err)
	}
	
	// Use the key for something
	fmt.Printf("Generated RSA key with size: %d\n", privateKey.N.BitLen())
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_3() {
	keySize := 1024
	// Using variable but still weak key size
	// ruleid: rule-weakkeystrength-updatedMIT
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		log.Fatal(err)
	}
	
	// Export public key
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		log.Fatal(err)
	}
	
	publicKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKeyBytes,
		},
	)
	ioutil.WriteFile("public_key.pem", publicKeyPEM, 0644)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_4() {
	// Using a constant but still weak key size
	const keyBits = 1024
	// ruleid: rule-weakkeystrength-updatedMIT
	privateKey, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		log.Fatal(err)
	}
	
	// Just print the modulus
	fmt.Printf("Modulus: %x\n", privateKey.N)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_5() {
	// Using 768 bits - uncommon but still weak
	// ruleid: rule-weakkeystrength-updatedMIT
	privateKey, err := rsa.GenerateKey(rand.Reader, 768)
	if err != nil {
		log.Fatal(err)
	}
	
	// Use the key for encryption (simplified)
	fmt.Printf("Generated key with exponent: %d\n", privateKey.E)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_6() {
	// Function that generates weak keys
	generateWeakKey := func() (*rsa.PrivateKey, error) {
		// ruleid: rule-weakkeystrength-updatedMIT
		return rsa.GenerateKey(rand.Reader, 1024)
	}
	
	key, err := generateWeakKey()
	if err != nil {
		log.Fatal(err)
	}
	
	fmt.Printf("Key generated with size: %d\n", key.N.BitLen())
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_7() {
	// Using a calculation that results in weak key size
	base := 512
	multiplier := 2
	// ruleid: rule-weakkeystrength-updatedMIT
	privateKey, err := rsa.GenerateKey(rand.Reader, base*multiplier) // 1024 bits
	if err != nil {
		log.Fatal(err)
	}
	
	fmt.Printf("Generated RSA key with %d bits\n", privateKey.N.BitLen())
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_8() {
	// Using environment variable but defaulting to weak key
	keySizeStr := os.Getenv("RSA_KEY_SIZE")
	keySize := 1024 // Default to weak key
	
	// ruleid: rule-weakkeystrength-updatedMIT
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		log.Fatal(err)
	}
	
	fmt.Printf("Generated %d-bit RSA key\n", privateKey.N.BitLen())
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_9() {
	// Using conditional but both branches are weak
	useStrongerKey := true
	var keySize int
	
	if useStrongerKey {
		keySize = 1536 // Still below recommended 2048
	} else {
		keySize = 1024 // Weak
	}
	
	// ruleid: rule-weakkeystrength-updatedMIT
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		log.Fatal(err)
	}
	
	fmt.Printf("Key size: %d bits\n", privateKey.N.BitLen())
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_10() {
	// Using a loop to generate multiple weak keys
	for i := 0; i < 3; i++ {
		// ruleid: rule-weakkeystrength-updatedMIT
		privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			log.Fatal(err)
		}
		
		fmt.Printf("Key %d: %d bits\n", i, privateKey.N.BitLen())
	}
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_11() {
	// Using bitshift to calculate key size, but still weak
	baseBits := 256
	// ruleid: rule-weakkeystrength-updatedMIT
	privateKey, err := rsa.GenerateKey(rand.Reader, baseBits << 2) // 1024 bits
	if err != nil {
		log.Fatal(err)
	}
	
	fmt.Printf("Generated key with %d bits\n", privateKey.N.BitLen())
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_12() {
	// Using a map to select key size
	keySizes := map[string]int{
		"weak":     512,
		"medium":   1024,
		"stronger": 1536, // Still below recommended
	}
	
	selectedSize := keySizes["medium"]
	// ruleid: rule-weakkeystrength-updatedMIT
	privateKey, err := rsa.GenerateKey(rand.Reader, selectedSize)
	if err != nil {
		log.Fatal(err)
	}
	
	fmt.Printf("Selected %d-bit key\n", privateKey.N.BitLen())
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_13() {
	// Using a function to determine key size but returning weak value
	getKeySize := func() int {
		return 1024
	}
	
	// ruleid: rule-weakkeystrength-updatedMIT
	privateKey, err := rsa.GenerateKey(rand.Reader, getKeySize())
	if err != nil {
		log.Fatal(err)
	}
	
	fmt.Printf("Function returned key size: %d\n", privateKey.N.BitLen())
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_14() {
	// Using a slice to store different key sizes and selecting a weak one
	keySizes := []int{512, 1024, 1536, 2048}
	selectedIndex := 1 // Selects 1024
	
	// ruleid: rule-weakkeystrength-updatedMIT
	privateKey, err := rsa.GenerateKey(rand.Reader, keySizes[selectedIndex])
	if err != nil {
		log.Fatal(err)
	}
	
	fmt.Printf("Selected key size from slice: %d\n", privateKey.N.BitLen())
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_15() {
	// Using mathematical operations resulting in weak key size
	a := 256
	b := 4
	c := 0
	
	// ruleid: rule-weakkeystrength-updatedMIT
	privateKey, err := rsa.GenerateKey(rand.Reader, a*b+c) // 1024 bits
	if err != nil {
		log.Fatal(err)
	}
	
	fmt.Printf("Calculated key size: %d bits\n", privateKey.N.BitLen())
}
// {/fact}

// True Negatives (Secure Cases)

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_1() {
	// Using 2048 bits for RSA key generation (recommended minimum)
	// ok: rule-weakkeystrength-updatedMIT
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	
	// Save the private key to a file
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyBytes,
		},
	)
	ioutil.WriteFile("private_key.pem", privateKeyPEM, 0600)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_2() {
	// Using 4096 bits for RSA key generation (stronger than recommended)
	// ok: rule-weakkeystrength-updatedMIT
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatal(err)
	}
	
	// Use the key for something
	fmt.Printf("Generated RSA key with size: %d\n", privateKey.N.BitLen())
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_3() {
	keySize := 3072 // Strong key size
	// ok: rule-weakkeystrength-updatedMIT
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		log.Fatal(err)
	}
	
	// Export public key
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		log.Fatal(err)
	}
	
	publicKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKeyBytes,
		},
	)
	ioutil.WriteFile("public_key.pem", publicKeyPEM, 0644)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_4() {
	// Using a constant with strong key size
	const keyBits = 2048
	// ok: rule-weakkeystrength-updatedMIT
	privateKey, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		log.Fatal(err)
	}
	
	// Just print the modulus
	fmt.Printf("Modulus: %x\n", privateKey.N)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_5() {
	// Using 8192 bits - very strong
	// ok: rule-weakkeystrength-updatedMIT
	privateKey, err := rsa.GenerateKey(rand.Reader, 8192)
	if err != nil {
		log.Fatal(err)
	}
	
	// Use the key for encryption (simplified)
	fmt.Printf("Generated key with exponent: %d\n", privateKey.E)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_6() {
	// Function that generates strong keys
	generateStrongKey := func() (*rsa.PrivateKey, error) {
		// ok: rule-weakkeystrength-updatedMIT
		return rsa.GenerateKey(rand.Reader, 2048)
	}
	
	key, err := generateStrongKey()
	if err != nil {
		log.Fatal(err)
	}
	
	fmt.Printf("Key generated with size: %d\n", key.N.BitLen())
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_7() {
	// Using a calculation that results in strong key size
	base := 1024
	multiplier := 2
	// ok: rule-weakkeystrength-updatedMIT
	privateKey, err := rsa.GenerateKey(rand.Reader, base*multiplier) // 2048 bits
	if err != nil {
		log.Fatal(err)
	}
	
	fmt.Printf("Generated RSA key with %d bits\n", privateKey.N.BitLen())
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_8() {
	// Using environment variable with strong default
	keySizeStr := os.Getenv("RSA_KEY_SIZE")
	keySize := 2048 // Default to strong key
	
	// ok: rule-weakkeystrength-updatedMIT
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		log.Fatal(err)
	}
	
	fmt.Printf("Generated %d-bit RSA key\n", privateKey.N.BitLen())
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_9() {
	// Using conditional with strong key sizes
	useStrongerKey := true
	var keySize int
	
	if useStrongerKey {
		keySize = 4096 // Very strong
	} else {
		keySize = 2048 // Still strong enough
	}
	
	// ok: rule-weakkeystrength-updatedMIT
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		log.Fatal(err)
	}
	
	fmt.Printf("Key size: %d bits\n", privateKey.N.BitLen())
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_10() {
	// Using a loop to generate multiple strong keys
	for i := 0; i < 3; i++ {
		// ok: rule-weakkeystrength-updatedMIT
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatal(err)
		}
		
		fmt.Printf("Key %d: %d bits\n", i, privateKey.N.BitLen())
	}
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_11() {
	// Using bitshift to calculate key size, resulting in strong key
	baseBits := 512
	// ok: rule-weakkeystrength-updatedMIT
	privateKey, err := rsa.GenerateKey(rand.Reader, baseBits << 2) // 2048 bits
	if err != nil {
		log.Fatal(err)
	}
	
	fmt.Printf("Generated key with %d bits\n", privateKey.N.BitLen())
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_12() {
	// Using a map to select key size with strong options
	keySizes := map[string]int{
		"standard": 2048,
		"strong":   3072,
		"stronger": 4096,
	}
	
	selectedSize := keySizes["standard"]
	// ok: rule-weakkeystrength-updatedMIT
	privateKey, err := rsa.GenerateKey(rand.Reader, selectedSize)
	if err != nil {
		log.Fatal(err)
	}
	
	fmt.Printf("Selected %d-bit key\n", privateKey.N.BitLen())
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_13() {
	// Using a function to determine key size returning strong value
	getKeySize := func() int {
		return 2048
	}
	
	// ok: rule-weakkeystrength-updatedMIT
	privateKey, err := rsa.GenerateKey(rand.Reader, getKeySize())
	if err != nil {
		log.Fatal(err)
	}
	
	fmt.Printf("Function returned key size: %d\n", privateKey.N.BitLen())
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_14() {
	// Using a slice to store different key sizes and selecting a strong one
	keySizes := []int{1024, 2048, 3072, 4096}
	selectedIndex := 1 // Selects 2048
	
	// ok: rule-weakkeystrength-updatedMIT
	privateKey, err := rsa.GenerateKey(rand.Reader, keySizes[selectedIndex])
	if err != nil {
		log.Fatal(err)
	}
	
	fmt.Printf("Selected key size from slice: %d\n", privateKey.N.BitLen())
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_15() {
	// Using mathematical operations resulting in strong key size
	a := 512
	b := 4
	c := 0
	
	// ok: rule-weakkeystrength-updatedMIT
	privateKey, err := rsa.GenerateKey(rand.Reader, a*b+c) // 2048 bits
	if err != nil {
		log.Fatal(err)
	}
	
	fmt.Printf("Calculated key size: %d bits\n", privateKey.N.BitLen())
}
// {/fact}

func main() {
	// This function is just a placeholder and doesn't need to be called
	fmt.Println("RSA Key Generation Examples")
}