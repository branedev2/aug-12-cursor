package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/flate"
	"compress/gzip"
	"compress/lzw"
	"compress/zlib"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/dsnet/compress/bzip2"
	"github.com/klauspost/compress/s2"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// True Positive Examples (Vulnerable Code)

// {fact rule=zip-bomb-attack@v1.0 defects=1}
func bad_case_1() {
	// Directly decompressing a gzip file without size limits
	file, err := os.Open("potentially_malicious.gz")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	// ruleid: rule-decompression_bomb-updatedMIT
	gzReader, err := gzip.NewReader(file)
	if err != nil {
		fmt.Println("Error creating gzip reader:", err)
		return
	}
	defer gzReader.Close()

	// Vulnerable: Reading all content without limits
	content, err := ioutil.ReadAll(gzReader)
	if err != nil {
		fmt.Println("Error reading gzip content:", err)
		return
	}

	fmt.Println("Decompressed size:", len(content))
}
// {/fact}

// {fact rule=zip-bomb-attack@v1.0 defects=1}
func bad_case_2() {
	// Directly decompressing a zip file without size limits
	zipReader, err := zip.OpenReader("potentially_malicious.zip")
	if err != nil {
		fmt.Println("Error opening zip file:", err)
		return
	}
	defer zipReader.Close()

	for _, file := range zipReader.File {
		// ruleid: rule-decompression_bomb-updatedMIT
		rc, err := file.Open()
		if err != nil {
			fmt.Println("Error opening file in zip:", err)
			continue
		}

		// Vulnerable: Reading all content without limits
		content, err := ioutil.ReadAll(rc)
		if err != nil {
			fmt.Println("Error reading zip content:", err)
			rc.Close()
			continue
		}
		rc.Close()

		fmt.Println("File:", file.Name, "Size:", len(content))
	}
}
// {/fact}

// {fact rule=zip-bomb-attack@v1.0 defects=1}
func bad_case_3() {
	// Directly decompressing a bzip2 file without size limits
	file, err := os.Open("potentially_malicious.bz2")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	// ruleid: rule-decompression_bomb-updatedMIT
	bzReader := bzip2.NewReader(file)

	// Vulnerable: Reading all content without limits
	content, err := ioutil.ReadAll(bzReader)
	if err != nil {
		fmt.Println("Error reading bzip2 content:", err)
		return
	}

	fmt.Println("Decompressed size:", len(content))
}
// {/fact}

// {fact rule=zip-bomb-attack@v1.0 defects=1}
func bad_case_4() {
	// Handling uploaded file via HTTP and decompressing without limits
	http.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		file, header, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "Error retrieving file", http.StatusBadRequest)
			return
		}
		defer file.Close()

		if strings.HasSuffix(header.Filename, ".gz") {
			// ruleid: rule-decompression_bomb-updatedMIT
			gzReader, err := gzip.NewReader(file)
			if err != nil {
				http.Error(w, "Error creating gzip reader", http.StatusInternalServerError)
				return
			}
			defer gzReader.Close()

			// Vulnerable: Reading all content without limits
			content, err := ioutil.ReadAll(gzReader)
			if err != nil {
				http.Error(w, "Error reading gzip content", http.StatusInternalServerError)
				return
			}

			w.Write([]byte(fmt.Sprintf("Decompressed size: %d", len(content))))
		}
	})
}
// {/fact}

// {fact rule=zip-bomb-attack@v1.0 defects=1}
func bad_case_5() {
	// Directly decompressing a zlib stream without size limits
	file, err := os.Open("potentially_malicious.zlib")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	// ruleid: rule-decompression_bomb-updatedMIT
	zlibReader, err := zlib.NewReader(file)
	if err != nil {
		fmt.Println("Error creating zlib reader:", err)
		return
	}
	defer zlibReader.Close()

	// Vulnerable: Reading all content without limits
	content, err := ioutil.ReadAll(zlibReader)
	if err != nil {
		fmt.Println("Error reading zlib content:", err)
		return
	}

	fmt.Println("Decompressed size:", len(content))
}
// {/fact}

// {fact rule=zip-bomb-attack@v1.0 defects=1}
func bad_case_6() {
	// Directly decompressing a flate stream without size limits
	file, err := os.Open("potentially_malicious.flate")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	// ruleid: rule-decompression_bomb-updatedMIT
	flateReader := flate.NewReader(file)
	defer flateReader.Close()

	// Vulnerable: Reading all content without limits
	content, err := ioutil.ReadAll(flateReader)
	if err != nil {
		fmt.Println("Error reading flate content:", err)
		return
	}

	fmt.Println("Decompressed size:", len(content))
}
// {/fact}

// {fact rule=zip-bomb-attack@v1.0 defects=1}
func bad_case_7() {
	// Directly decompressing an LZW stream without size limits
	file, err := os.Open("potentially_malicious.lzw")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	// ruleid: rule-decompression_bomb-updatedMIT
	lzwReader := lzw.NewReader(file, lzw.LSB, 8)
	defer lzwReader.Close()

	// Vulnerable: Reading all content without limits
	content, err := ioutil.ReadAll(lzwReader)
	if err != nil {
		fmt.Println("Error reading LZW content:", err)
		return
	}

	fmt.Println("Decompressed size:", len(content))
}
// {/fact}

// {fact rule=zip-bomb-attack@v1.0 defects=1}
func bad_case_8() {
	// Directly decompressing a zstd stream without size limits
	file, err := os.Open("potentially_malicious.zst")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	// ruleid: rule-decompression_bomb-updatedMIT
	zstdReader, err := zstd.NewReader(file)
	if err != nil {
		fmt.Println("Error creating zstd reader:", err)
		return
	}
	defer zstdReader.Close()

	// Vulnerable: Reading all content without limits
	content, err := ioutil.ReadAll(zstdReader)
	if err != nil {
		fmt.Println("Error reading zstd content:", err)
		return
	}

	fmt.Println("Decompressed size:", len(content))
}
// {/fact}

// {fact rule=zip-bomb-attack@v1.0 defects=1}
func bad_case_9() {
	// Directly decompressing a brotli stream without size limits
	file, err := os.Open("potentially_malicious.br")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	// ruleid: rule-decompression_bomb-updatedMIT
	brReader := brotli.NewReader(file)

	// Vulnerable: Reading all content without limits
	content, err := ioutil.ReadAll(brReader)
	if err != nil {
		fmt.Println("Error reading brotli content:", err)
		return
	}

	fmt.Println("Decompressed size:", len(content))
}
// {/fact}

// {fact rule=zip-bomb-attack@v1.0 defects=1}
func bad_case_10() {
	// Directly decompressing an XZ stream without size limits
	file, err := os.Open("potentially_malicious.xz")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	// ruleid: rule-decompression_bomb-updatedMIT
	xzReader, err := xz.NewReader(file)
	if err != nil {
		fmt.Println("Error creating xz reader:", err)
		return
	}

	// Vulnerable: Reading all content without limits
	content, err := ioutil.ReadAll(xzReader)
	if err != nil {
		fmt.Println("Error reading xz content:", err)
		return
	}

	fmt.Println("Decompressed size:", len(content))
}
// {/fact}

// {fact rule=zip-bomb-attack@v1.0 defects=1}
func bad_case_11() {
	// Directly decompressing a tar.gz file without size limits
	file, err := os.Open("potentially_malicious.tar.gz")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	// ruleid: rule-decompression_bomb-updatedMIT
	gzReader, err := gzip.NewReader(file)
	if err != nil {
		fmt.Println("Error creating gzip reader:", err)
		return
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Println("Error reading tar header:", err)
			return
		}

		// Vulnerable: Reading all content without limits
		content, err := ioutil.ReadAll(tarReader)
		if err != nil {
			fmt.Println("Error reading tar content:", err)
			continue
		}

		fmt.Println("File:", header.Name, "Size:", len(content))
	}
}
// {/fact}

// {fact rule=zip-bomb-attack@v1.0 defects=1}
func bad_case_12() {
	// Directly decompressing an S2 stream without size limits
	file, err := os.Open("potentially_malicious.s2")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	// ruleid: rule-decompression_bomb-updatedMIT
	s2Reader := s2.NewReader(file)

	// Vulnerable: Reading all content without limits
	content, err := ioutil.ReadAll(s2Reader)
	if err != nil {
		fmt.Println("Error reading S2 content:", err)
		return
	}

	fmt.Println("Decompressed size:", len(content))
}
// {/fact}

// {fact rule=zip-bomb-attack@v1.0 defects=1}
func bad_case_13() {
	// Directly decompressing a gzip stream from HTTP response without size limits
	resp, err := http.Get("https://example.com/potentially_malicious.gz")
	if err != nil {
		fmt.Println("Error fetching file:", err)
		return
	}
	defer resp.Body.Close()

	// ruleid: rule-decompression_bomb-updatedMIT
	gzReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		fmt.Println("Error creating gzip reader:", err)
		return
	}
	defer gzReader.Close()

	// Vulnerable: Reading all content without limits
	content, err := ioutil.ReadAll(gzReader)
	if err != nil {
		fmt.Println("Error reading gzip content:", err)
		return
	}

	fmt.Println("Decompressed size:", len(content))
}
// {/fact}

// {fact rule=zip-bomb-attack@v1.0 defects=1}
func bad_case_14() {
	// Directly decompressing a gzip byte buffer without size limits
	compressedData := []byte{/* some compressed data */}
	buffer := bytes.NewBuffer(compressedData)

	// ruleid: rule-decompression_bomb-updatedMIT
	gzReader, err := gzip.NewReader(buffer)
	if err != nil {
		fmt.Println("Error creating gzip reader:", err)
		return
	}
	defer gzReader.Close()

	// Vulnerable: Reading all content without limits
	content, err := ioutil.ReadAll(gzReader)
	if err != nil {
		fmt.Println("Error reading gzip content:", err)
		return
	}

	fmt.Println("Decompressed size:", len(content))
}
// {/fact}

// {fact rule=zip-bomb-attack@v1.0 defects=1}
func bad_case_15() {
	// Extracting zip files to disk without size limits
	zipReader, err := zip.OpenReader("potentially_malicious.zip")
	if err != nil {
		fmt.Println("Error opening zip file:", err)
		return
	}
	defer zipReader.Close()

	for _, file := range zipReader.File {
		// ruleid: rule-decompression_bomb-updatedMIT
		rc, err := file.Open()
		if err != nil {
			fmt.Println("Error opening file in zip:", err)
			continue
		}

		// Create output file
		path := filepath.Join("output_dir", file.Name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			fmt.Println("Error creating directory:", err)
			rc.Close()
			continue
		}

		outFile, err := os.Create(path)
		if err != nil {
			fmt.Println("Error creating output file:", err)
			rc.Close()
			continue
		}

		// Vulnerable: Copying all content without limits
		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()

		if err != nil {
			fmt.Println("Error extracting file:", err)
			continue
		}
	}
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=zip-bomb-attack@v1.0 defects=0}
func good_case_1() {
	// Safely decompressing a gzip file with size limits
	file, err := os.Open("potentially_malicious.gz")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		fmt.Println("Error creating gzip reader:", err)
		return
	}
	defer gzReader.Close()

	// ok: rule-decompression_bomb-updatedMIT
	limitedReader := io.LimitReader(gzReader, 1024*1024*10) // 10MB limit
	content, err := ioutil.ReadAll(limitedReader)
	if err != nil {
		fmt.Println("Error reading gzip content:", err)
		return
	}

	fmt.Println("Decompressed size:", len(content))
}
// {/fact}

// {fact rule=zip-bomb-attack@v1.0 defects=0}
func good_case_2() {
	// Safely decompressing a zip file with size limits
	zipReader, err := zip.OpenReader("potentially_malicious.zip")
	if err != nil {
		fmt.Println("Error opening zip file:", err)
		return
	}
	defer zipReader.Close()

	for _, file := range zipReader.File {
		// Check file size before extraction
		if file.UncompressedSize64 > 1024*1024*10 { // 10MB limit
			fmt.Println("File too large:", file.Name)
			continue
		}

		rc, err := file.Open()
		if err != nil {
			fmt.Println("Error opening file in zip:", err)
			continue
		}

		// ok: rule-decompression_bomb-updatedMIT
		limitedReader := io.LimitReader(rc, 1024*1024*10) // 10MB limit as additional safety
		content, err := ioutil.ReadAll(limitedReader)
		rc.Close()
		if err != nil {
			fmt.Println("Error reading zip content:", err)
			continue
		}

		fmt.Println("File:", file.Name, "Size:", len(content))
	}
}
// {/fact}

// {fact rule=zip-bomb-attack@v1.0 defects=0}
func good_case_3() {
	// Safely decompressing a bzip2 file with size limits
	file, err := os.Open("potentially_malicious.bz2")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	bzReader := bzip2.NewReader(file)

	// ok: rule-decompression_bomb-updatedMIT
	limitedReader := io.LimitReader(bzReader, 1024*1024*10) // 10MB limit
	content, err := ioutil.ReadAll(limitedReader)
	if err != nil {
		fmt.Println("Error reading bzip2 content:", err)
		return
	}

	fmt.Println("Decompressed size:", len(content))
}
// {/fact}

// {fact rule=zip-bomb-attack@v1.0 defects=0}
func good_case_4() {
	// Safely handling uploaded file via HTTP and decompressing with limits
	http.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		file, header, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "Error retrieving file", http.StatusBadRequest)
			return
		}
		defer file.Close()

		if strings.HasSuffix(header.Filename, ".gz") {
			gzReader, err := gzip.NewReader(file)
			if err != nil {
				http.Error(w, "Error creating gzip reader", http.StatusInternalServerError)
				return
			}
			defer gzReader.Close()

			// ok: rule-decompression_bomb-updatedMIT
			limitedReader := io.LimitReader(gzReader, 1024*1024*10) // 10MB limit
			content, err := ioutil.ReadAll(limitedReader)
			if err != nil {
				http.Error(w, "Error reading gzip content", http.StatusInternalServerError)
				return
			}

			w.Write([]byte(fmt.Sprintf("Decompressed size: %d", len(content))))
		}
	})
}
// {/fact}

// {fact rule=zip-bomb-attack@v1.0 defects=0}
func good_case_5() {
	// Safely decompressing a zlib stream with size limits
	file, err := os.Open("potentially_malicious.zlib")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	zlibReader, err := zlib.NewReader(file)
	if err != nil {
		fmt.Println("Error creating zlib reader:", err)
		return
	}
	defer zlibReader.Close()

	// ok: rule-decompression_bomb-updatedMIT
	limitedReader := io.LimitReader(zlibReader, 1024*1024*10) // 10MB limit
	content, err := ioutil.ReadAll(limitedReader)
	if err != nil {
		fmt.Println("Error reading zlib content:", err)
		return
	}

	fmt.Println("Decompressed size:", len(content))
}
// {/fact}

// {fact rule=zip-bomb-attack@v1.0 defects=0}
func good_case_6() {
	// Safely decompressing a flate stream with size limits
	file, err := os.Open("potentially_malicious.flate")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	flateReader := flate.NewReader(file)
	defer flateReader.Close()

	// ok: rule-decompression_bomb-updatedMIT
	limitedReader := io.LimitReader(flateReader, 1024*1024*10) // 10MB limit
	content, err := ioutil.ReadAll(limitedReader)
	if err != nil {
		fmt.Println("Error reading flate content:", err)
		return
	}

	fmt.Println("Decompressed size:", len(content))
}
// {/fact}

// {fact rule=zip-bomb-attack@v1.0 defects=0}
func good_case_7() {
	// Safely decompressing an LZW stream with size limits
	file, err := os.Open("potentially_malicious.lzw")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	lzwReader := lzw.NewReader(file, lzw.LSB, 8)
	defer lzwReader.Close()

	// ok: rule-decompression_bomb-updatedMIT
	limitedReader := io.LimitReader(lzwReader, 1024*1024*10) // 10MB limit
	content, err := ioutil.ReadAll(limitedReader)
	if err != nil {
		fmt.Println("Error reading LZW content:", err)
		return
	}

	fmt.Println("Decompressed size:", len(content))
}
// {/fact}

// {fact rule=zip-bomb-attack@v1.0 defects=0}
func good_case_8() {
	// Safely decompressing a zstd stream with size limits
	file, err := os.Open("potentially_malicious.zst")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	zstdReader, err := zstd.NewReader(file)
	if err != nil {
		fmt.Println("Error creating zstd reader:", err)
		return
	}
	defer zstdReader.Close()

	// ok: rule-decompression_bomb-updatedMIT
	limitedReader := io.LimitReader(zstdReader, 1024*1024*10) // 10MB limit
	content, err := ioutil.ReadAll(limitedReader)
	if err != nil {
		fmt.Println("Error reading zstd content:", err)
		return
	}

	fmt.Println("Decompressed size:", len(content))
}
// {/fact}

// {fact rule=zip-bomb-attack@v1.0 defects=0}
func good_case_9() {
	// Safely decompressing a brotli stream with size limits
	file, err := os.Open("potentially_malicious.br")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	brReader := brotli.NewReader(file)

	// ok: rule-decompression_bomb-updatedMIT
	limitedReader := io.LimitReader(brReader, 1024*1024*10) // 10MB limit
	content, err := ioutil.ReadAll(limitedReader)
	if err != nil {
		fmt.Println("Error reading brotli content:", err)
		return
	}

	fmt.Println("Decompressed size:", len(content))
}
// {/fact}

// {fact rule=zip-bomb-attack@v1.0 defects=0}
func good_case_10() {
	// Safely decompressing an XZ stream with size limits
	file, err := os.Open("potentially_malicious.xz")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	xzReader, err := xz.NewReader(file)
	if err != nil {
		fmt.Println("Error creating xz reader:", err)
		return
	}

	// ok: rule-decompression_bomb-updatedMIT
	limitedReader := io.LimitReader(xzReader, 1024*1024*10) // 10MB limit
	content, err := ioutil.ReadAll(limitedReader)
	if err != nil {
		fmt.Println("Error reading xz content:", err)
		return
	}

	fmt.Println("Decompressed size:", len(content))
}
// {/fact}

// {fact rule=zip-bomb-attack@v1.0 defects=0}
func good_case_11() {
	// Safely decompressing a tar.gz file with size limits
	file, err := os.Open("potentially_malicious.tar.gz")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		fmt.Println("Error creating gzip reader:", err)
		return
	}
	defer gzReader.Close()

	// ok: rule-decompression_bomb-updatedMIT
	limitedGzReader := io.LimitReader(gzReader, 1024*1024*100) // 100MB limit for the entire archive
	tarReader := tar.NewReader(limitedGzReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Println("Error reading tar header:", err)
			return
		}

		// Additional limit per file
		limitedFileReader := io.LimitReader(tarReader, 1024*1024*10) // 10MB limit per file
		content, err := ioutil.ReadAll(limitedFileReader)
		if err != nil {
			fmt.Println("Error reading tar content:", err)
			continue
		}

		fmt.Println("File:", header.Name, "Size:", len(content))
	}
}
// {/fact}

// {fact rule=zip-bomb-attack@v1.0 defects=0}
func good_case_12() {
	// Safely decompressing an S2 stream with size limits
	file, err := os.Open("potentially_malicious.s2")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	s2Reader := s2.NewReader(file)

	// ok: rule-decompression_bomb-updatedMIT
	limitedReader := io.LimitReader(s2Reader, 1024*1024*10) // 10MB limit
	content, err := ioutil.ReadAll(limitedReader)
	if err != nil {
		fmt.Println("Error reading S2 content:", err)
		return
	}

	fmt.Println("Decompressed size:", len(content))
}
// {/fact}

// {fact rule=zip-bomb-attack@v1.0 defects=0}
func good_case_13() {
	// Safely decompressing a gzip stream from HTTP response with size limits
	resp, err := http.Get("https://example.com/potentially_malicious.gz")
	if err != nil {
		fmt.Println("Error fetching file:", err)
		return
	}
	defer resp.Body.Close()

	gzReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		fmt.Println("Error creating gzip reader:", err)
		return
	}
	defer gzReader.Close()

	// ok: rule-decompression_bomb-updatedMIT
	limitedReader := io.LimitReader(gzReader, 1024*1024*10) // 10MB limit
	content, err := ioutil.ReadAll(limitedReader)
	if err != nil {
		fmt.Println("Error reading gzip content:", err)
		return
	}

	fmt.Println("Decompressed size:", len(content))
}
// {/fact}

// {fact rule=zip-bomb-attack@v1.0 defects=0}
func good_case_14() {
	// Safely decompressing a gzip byte buffer with size limits
	compressedData := []byte{/* some compressed data */}
	buffer := bytes.NewBuffer(compressedData)

	gzReader, err := gzip.NewReader(buffer)
	if err != nil {
		fmt.Println("Error creating gzip reader:", err)
		return
	}
	defer gzReader.Close()

	// ok: rule-decompression_bomb-updatedMIT
	limitedReader := io.LimitReader(gzReader, 1024*1024*10) // 10MB limit
	content, err := ioutil.ReadAll(limitedReader)
	if err != nil {
		fmt.Println("Error reading gzip content:", err)
		return
	}

	fmt.Println("Decompressed size:", len(content))
}
// {/fact}

// {fact rule=zip-bomb-attack@v1.0 defects=0}
func good_case_15() {
	// Safely extracting zip files to disk with size limits
	zipReader, err := zip.OpenReader("potentially_malicious.zip")
	if err != nil {
		fmt.Println("Error opening zip file:", err)
		return
	}
	defer zipReader.Close()

	for _, file := range zipReader.File {
		// Check file size before extraction
		if file.UncompressedSize64 > 1024*1024*10 { // 10MB limit
			fmt.Println("File too large:", file.Name)
			continue
		}

		rc, err := file.Open()
		if err != nil {
			fmt.Println("Error opening file in zip:", err)
			continue
		}

		// Create output file
		path := filepath.Join("output_dir", file.Name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			fmt.Println("Error creating directory:", err)
			rc.Close()
			continue
		}

		outFile, err := os.Create(path)
		if err != nil {
			fmt.Println("Error creating output file:", err)
			rc.Close()
			continue
		}

		// ok: rule-decompression_bomb-updatedMIT
		limitedReader := io.LimitReader(rc, 1024*1024*10) // 10MB limit
		_, err = io.Copy(outFile, limitedReader)
		outFile.Close()
		rc.Close()

		if err != nil {
			fmt.Println("Error extracting file:", err)
			continue
		}
	}
}
// {/fact}

func main() {
	// This function is just a placeholder to make the code compilable
	fmt.Println("Decompression bomb vulnerability examples")
}