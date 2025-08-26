package main

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// BAD CASES - Resource leaks that should be detected

// {fact rule=resource-leak@v1.0 defects=1}
func bad_case_1() {
	// ruleid: rule-resource-leak
	file, err := os.Open("example.txt")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	
	// File is opened but never closed
	data := make([]byte, 100)
	_, err = file.Read(data)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}
	fmt.Println("Data read successfully")
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
func bad_case_2() {
	// ruleid: rule-resource-leak
	file, err := os.Create("output.txt")
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	
	// File is created but never closed
	_, err = file.WriteString("Hello, World!")
	if err != nil {
		fmt.Println("Error writing to file:", err)
		return
	}
	fmt.Println("Data written successfully")
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
func bad_case_3() {
	// ruleid: rule-resource-leak
	file, err := os.OpenFile("data.txt", os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	
	// Early return without closing the file
	if info, err := file.Stat(); err != nil {
		fmt.Println("Error getting file info:", err)
		return
	} else if info.Size() == 0 {
		fmt.Println("File is empty")
		return
	}
	
	fmt.Println("File processing complete")
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
func bad_case_4() {
	// Function that conditionally opens files but doesn't close them
	for i := 0; i < 3; i++ {
		filename := fmt.Sprintf("file%d.txt", i)
		
		// ruleid: rule-resource-leak
		file, err := os.Open(filename)
		if err != nil {
			continue // Skip to next file without closing
		}
		
		data := make([]byte, 100)
		file.Read(data)
		// No close before next iteration
	}
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
func bad_case_5() {
	// ruleid: rule-resource-leak
	srcFile, err := os.Open("source.txt")
	if err != nil {
		fmt.Println("Error opening source file:", err)
		return
	}
	
	// ruleid: rule-resource-leak
	dstFile, err := os.Create("destination.txt")
	if err != nil {
		fmt.Println("Error creating destination file:", err)
		return
	}
	
	// Both files opened but neither closed
	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		fmt.Println("Error copying data:", err)
		return
	}
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
func bad_case_6() {
	// Opening multiple files in a loop without closing
	files := []string{"file1.txt", "file2.txt", "file3.txt"}
	
	for _, filename := range files {
		// ruleid: rule-resource-leak
		file, err := os.Open(filename)
		if err != nil {
			fmt.Println("Error opening file:", err)
			continue
		}
		
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fmt.Println(scanner.Text())
		}
		// No close before next iteration
	}
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
func bad_case_7() {
	// ruleid: rule-resource-leak
	file, err := os.Open("config.json")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	
	// Using a panic which prevents proper cleanup
	data := make([]byte, 100)
	_, err = file.Read(data)
	if err != nil {
		panic("Failed to read config file")
	}
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
func bad_case_8() {
	// ruleid: rule-resource-leak
	file, err := os.OpenFile("log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening log file:", err)
		return
	}
	
	// Using the file but forgetting to close in a complex control flow
	if _, err := file.WriteString("Log entry 1\n"); err != nil {
		fmt.Println("Error writing to log:", err)
		return
	}
	
	if someCondition() {
		if _, err := file.WriteString("Conditional log entry\n"); err != nil {
			fmt.Println("Error writing conditional log:", err)
			return
		}
		fmt.Println("Conditional logging complete")
	}
	
	// File never closed
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
func bad_case_9() {
	dirPath := "data_directory"
	
	// ruleid: rule-resource-leak
	dir, err := os.Open(dirPath)
	if err != nil {
		fmt.Println("Error opening directory:", err)
		return
	}
	
	// Reading directory entries without closing the directory handle
	entries, err := dir.Readdir(-1)
	if err != nil {
		fmt.Println("Error reading directory:", err)
		return
	}
	
	for _, entry := range entries {
		fmt.Println(entry.Name())
	}
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
func bad_case_10() {
	// ruleid: rule-resource-leak
	file, err := os.Open("large_file.dat")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	
	// Creating a reader but not closing the underlying file
	reader := bufio.NewReader(file)
	
	for {
		line, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		} else if err != nil {
			fmt.Println("Error reading line:", err)
			return
		}
		fmt.Print(line)
	}
	// File never closed
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
func bad_case_11() {
	// ruleid: rule-resource-leak
	file, err := os.Open("compressed.gz")
	if err != nil {
		fmt.Println("Error opening compressed file:", err)
		return
	}
	
	// Creating a gzip reader but not closing the underlying file
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		fmt.Println("Error creating gzip reader:", err)
		return
	}
	defer gzipReader.Close() // Only closing the gzip reader, not the file
	
	data, err := io.ReadAll(gzipReader)
	if err != nil {
		fmt.Println("Error reading compressed data:", err)
		return
	}
	fmt.Println("Read", len(data), "bytes")
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
func bad_case_12() {
	http.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		// ruleid: rule-resource-leak
		file, err := os.Create("uploaded_file.dat")
		if err != nil {
			http.Error(w, "Failed to create file", http.StatusInternalServerError)
			return
		}
		
		// Copying from request body to file without closing the file
		_, err = io.Copy(file, r.Body)
		if err != nil {
			http.Error(w, "Failed to save file", http.StatusInternalServerError)
			return
		}
		
		w.Write([]byte("Upload successful"))
		// File never closed
	})
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
func bad_case_13() {
	// ruleid: rule-resource-leak
	file, err := os.Open("data.bin")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	
	// Using a nested function that might cause the file to be forgotten
	processData := func() error {
		data := make([]byte, 1024)
		_, err := file.Read(data)
		return err
	}
	
	if err := processData(); err != nil {
		fmt.Println("Error processing data:", err)
		return
	}
	
	// More operations without closing the file
	fmt.Println("Processing complete")
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
func bad_case_14() {
	// Opening multiple files with different methods
	// ruleid: rule-resource-leak
	file1, err := os.Open("input.txt")
	if err != nil {
		fmt.Println("Error opening input file:", err)
		return
	}
	
	// ruleid: rule-resource-leak
	file2, err := os.OpenFile("output.txt", os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		fmt.Println("Error opening output file:", err)
		return
	}
	
	data := make([]byte, 1024)
	n, err := file1.Read(data)
	if err != nil && err != io.EOF {
		fmt.Println("Error reading data:", err)
		return
	}
	
	_, err = file2.Write(data[:n])
	if err != nil {
		fmt.Println("Error writing data:", err)
		return
	}
	
	// Neither file is closed
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
func bad_case_15() {
	// Using filepath.Walk with unclosed files
	filepath.Walk("./data", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if !info.IsDir() && filepath.Ext(path) == ".txt" {
			// ruleid: rule-resource-leak
			file, err := os.Open(path)
			if err != nil {
				fmt.Println("Error opening file:", path, err)
				return nil // Continue walking
			}
			
			// Process the file
			data := make([]byte, 100)
			file.Read(data)
			fmt.Println("First 100 bytes of", path, ":", string(data))
			// File not closed before next iteration
		}
		return nil
	})
}
// {/fact}

// GOOD CASES - Properly managed resources that should not be detected

// {fact rule=resource-leak@v1.0 defects=0}
func good_case_1() {
	// ok: rule-resource-leak
	file, err := os.Open("example.txt")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()
	
	data := make([]byte, 100)
	_, err = file.Read(data)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}
	fmt.Println("Data read successfully")
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
func good_case_2() {
	// ok: rule-resource-leak
	file, err := os.Create("output.txt")
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()
	
	_, err = file.WriteString("Hello, World!")
	if err != nil {
		fmt.Println("Error writing to file:", err)
		return
	}
	fmt.Println("Data written successfully")
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
func good_case_3() {
	// ok: rule-resource-leak
	file, err := os.OpenFile("data.txt", os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()
	
	// Early return is safe because of defer
	if info, err := file.Stat(); err != nil {
		fmt.Println("Error getting file info:", err)
		return
	} else if info.Size() == 0 {
		fmt.Println("File is empty")
		return
	}
	
	fmt.Println("File processing complete")
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
func good_case_4() {
	// Function that properly closes files in a loop
	for i := 0; i < 3; i++ {
		filename := fmt.Sprintf("file%d.txt", i)
		
		// ok: rule-resource-leak
		file, err := os.Open(filename)
		if err != nil {
			continue
		}
		defer file.Close() // This is actually not ideal in a loop, but technically prevents leak
		
		data := make([]byte, 100)
		file.Read(data)
	}
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
func good_case_5() {
	// ok: rule-resource-leak
	srcFile, err := os.Open("source.txt")
	if err != nil {
		fmt.Println("Error opening source file:", err)
		return
	}
	defer srcFile.Close()
	
	// ok: rule-resource-leak
	dstFile, err := os.Create("destination.txt")
	if err != nil {
		fmt.Println("Error creating destination file:", err)
		return
	}
	defer dstFile.Close()
	
	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		fmt.Println("Error copying data:", err)
		return
	}
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
func good_case_6() {
	// Better pattern for opening files in a loop
	files := []string{"file1.txt", "file2.txt", "file3.txt"}
	
	for _, filename := range files {
		func() {
			// ok: rule-resource-leak
			file, err := os.Open(filename)
			if err != nil {
				fmt.Println("Error opening file:", err)
				return
			}
			defer file.Close()
			
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				fmt.Println(scanner.Text())
			}
		}() // Immediately invoked function ensures defer works per iteration
	}
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
func good_case_7() {
	// ok: rule-resource-leak
	file, err := os.Open("config.json")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()
	
	// Even with panic, defer ensures cleanup
	data := make([]byte, 100)
	_, err = file.Read(data)
	if err != nil {
		panic("Failed to read config file")
	}
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
func good_case_8() {
	// ok: rule-resource-leak
	file, err := os.OpenFile("log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening log file:", err)
		return
	}
	defer file.Close()
	
	// Complex control flow with proper cleanup
	if _, err := file.WriteString("Log entry 1\n"); err != nil {
		fmt.Println("Error writing to log:", err)
		return
	}
	
	if someCondition() {
		if _, err := file.WriteString("Conditional log entry\n"); err != nil {
			fmt.Println("Error writing conditional log:", err)
			return
		}
		fmt.Println("Conditional logging complete")
	}
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
func good_case_9() {
	dirPath := "data_directory"
	
	// ok: rule-resource-leak
	dir, err := os.Open(dirPath)
	if err != nil {
		fmt.Println("Error opening directory:", err)
		return
	}
	defer dir.Close()
	
	entries, err := dir.Readdir(-1)
	if err != nil {
		fmt.Println("Error reading directory:", err)
		return
	}
	
	for _, entry := range entries {
		fmt.Println(entry.Name())
	}
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
func good_case_10() {
	// ok: rule-resource-leak
	file, err := os.Open("large_file.dat")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()
	
	reader := bufio.NewReader(file)
	
	for {
		line, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		} else if err != nil {
			fmt.Println("Error reading line:", err)
			return
		}
		fmt.Print(line)
	}
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
func good_case_11() {
	// ok: rule-resource-leak
	file, err := os.Open("compressed.gz")
	if err != nil {
		fmt.Println("Error opening compressed file:", err)
		return
	}
	defer file.Close()
	
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		fmt.Println("Error creating gzip reader:", err)
		return
	}
	defer gzipReader.Close()
	
	data, err := io.ReadAll(gzipReader)
	if err != nil {
		fmt.Println("Error reading compressed data:", err)
		return
	}
	fmt.Println("Read", len(data), "bytes")
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
func good_case_12() {
	http.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		// ok: rule-resource-leak
		file, err := os.Create("uploaded_file.dat")
		if err != nil {
			http.Error(w, "Failed to create file", http.StatusInternalServerError)
			return
		}
		defer file.Close()
		
		_, err = io.Copy(file, r.Body)
		if err != nil {
			http.Error(w, "Failed to save file", http.StatusInternalServerError)
			return
		}
		
		w.Write([]byte("Upload successful"))
	})
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
func good_case_13() {
	// ok: rule-resource-leak
	file, err := os.Open("data.bin")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()
	
	// Using a nested function with proper file handling
	processData := func() error {
		data := make([]byte, 1024)
		_, err := file.Read(data)
		return err
	}
	
	if err := processData(); err != nil {
		fmt.Println("Error processing data:", err)
		return
	}
	
	fmt.Println("Processing complete")
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
func good_case_14() {
	// Explicitly closing files without defer
	// ok: rule-resource-leak
	file1, err := os.Open("input.txt")
	if err != nil {
		fmt.Println("Error opening input file:", err)
		return
	}
	
	// ok: rule-resource-leak
	file2, err := os.OpenFile("output.txt", os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		file1.Close() // Explicitly close first file on error
		fmt.Println("Error opening output file:", err)
		return
	}
	
	data := make([]byte, 1024)
	n, err := file1.Read(data)
	if err != nil && err != io.EOF {
		file1.Close()
		file2.Close()
		fmt.Println("Error reading data:", err)
		return
	}
	
	_, err = file2.Write(data[:n])
	if err != nil {
		file1.Close()
		file2.Close()
		fmt.Println("Error writing data:", err)
		return
	}
	
	file1.Close()
	file2.Close()
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
func good_case_15() {
	// Using filepath.Walk with properly closed files
	filepath.Walk("./data", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if !info.IsDir() && filepath.Ext(path) == ".txt" {
			func() {
				// ok: rule-resource-leak
				file, err := os.Open(path)
				if err != nil {
					fmt.Println("Error opening file:", path, err)
					return
				}
				defer file.Close()
				
				// Process the file
				data := make([]byte, 100)
				file.Read(data)
				fmt.Println("First 100 bytes of", path, ":", string(data))
			}()
		}
		return nil
	})
}
// {/fact}

// Helper function for examples
func someCondition() bool {
	return true
}

func main() {
	fmt.Println("Resource leak detection examples")
}