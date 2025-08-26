package main

import (
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/antchfx/xmlquery"
	"github.com/beevik/etree"
	"github.com/clbanning/mxj"
	"golang.org/x/net/html/charset"
	"libxml/parser"
	"libxml/tree"
)

// TRUE POSITIVES (Vulnerable Code)

// bad_case_1 uses XMLParseNoEnt with encoding/xml package
// {fact rule=xml-external-entity@v1.0 defects=1}
func bad_case_1(w http.ResponseWriter, r *http.Request) {
	xmlData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	decoder := xml.NewDecoder(strings.NewReader(string(xmlData)))
	// ruleid: rule-xml-external-entity
	decoder.Entity = xml.HTMLEntity
	decoder.Strict = false
	decoder.AutoClose = xml.HTMLAutoClose
	decoder.DefaultSpace = "ns"
	decoder.CharsetReader = charset.NewReaderLabel
	var result interface{}
	err = decoder.Decode(&result)
	if err != nil {
		http.Error(w, "Failed to parse XML", http.StatusBadRequest)
		return
	}
	fmt.Fprintf(w, "XML parsed successfully")
}
// {/fact}

// bad_case_2 uses libxml2 with XML_PARSE_NOENT flag
// {fact rule=xml-external-entity@v1.0 defects=1}
func bad_case_2(w http.ResponseWriter, r *http.Request) {
	xmlData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	// ruleid: rule-xml-external-entity
	doc := parser.ReadMemory(string(xmlData), "", "", parser.XML_PARSE_NOENT)
	defer doc.Free()

	rootElement := doc.RootElement()
	content := rootElement.Content()
	fmt.Fprintf(w, "Parsed XML content: %s", content)
}
// {/fact}

// bad_case_3 uses libxml2 with XML_PARSE_NOENT in options
// {fact rule=xml-external-entity@v1.0 defects=1}
func bad_case_3(w http.ResponseWriter, r *http.Request) {
	xmlData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	options := parser.XML_PARSE_RECOVER | parser.XML_PARSE_NOBLANKS
	// ruleid: rule-xml-external-entity
	options |= parser.XML_PARSE_NOENT
	doc := parser.ReadMemory(string(xmlData), "", "", options)
	defer doc.Free()

	fmt.Fprintf(w, "XML parsed with custom options")
}
// {/fact}

// bad_case_4 uses xmlquery with disallowXXE set to false
// {fact rule=xml-external-entity@v1.0 defects=1}
func bad_case_4(w http.ResponseWriter, r *http.Request) {
	xmlData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	// ruleid: rule-xml-external-entity
	doc, err := xmlquery.Parse(strings.NewReader(string(xmlData)), xmlquery.ParserOptions{DisallowXXE: false})
	if err != nil {
		http.Error(w, "Failed to parse XML", http.StatusBadRequest)
		return
	}

	result := xmlquery.Find(doc, "//data")
	fmt.Fprintf(w, "Found %d data elements", len(result))
}
// {/fact}

// bad_case_5 uses mxj with XMLParseNoEnt
// {fact rule=xml-external-entity@v1.0 defects=1}
func bad_case_5(w http.ResponseWriter, r *http.Request) {
	xmlData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	// ruleid: rule-xml-external-entity
	mxj.SetParseNoEnt(true)
	m, err := mxj.NewMapXml(xmlData)
	if err != nil {
		http.Error(w, "Failed to parse XML", http.StatusBadRequest)
		return
	}

	fmt.Fprintf(w, "XML parsed into map: %v", m)
}
// {/fact}

// bad_case_6 uses etree with entity processing enabled
// {fact rule=xml-external-entity@v1.0 defects=1}
func bad_case_6(w http.ResponseWriter, r *http.Request) {
	xmlData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	doc := etree.NewDocument()
	// ruleid: rule-xml-external-entity
	doc.Entity = map[string]string{
		"xxe": "external",
	}
	doc.EnableEntityProcessing = true
	err = doc.ReadFromBytes(xmlData)
	if err != nil {
		http.Error(w, "Failed to parse XML", http.StatusBadRequest)
		return
	}

	fmt.Fprintf(w, "XML parsed with etree")
}
// {/fact}

// bad_case_7 uses libxml2 with XML_PARSE_NOENT in a complex options setting
// {fact rule=xml-external-entity@v1.0 defects=1}
func bad_case_7(w http.ResponseWriter, r *http.Request) {
	xmlData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	// Setting multiple options including the dangerous one
	options := parser.XML_PARSE_RECOVER | parser.XML_PARSE_NOBLANKS | parser.XML_PARSE_NOERROR
	// ruleid: rule-xml-external-entity
	options |= parser.XML_PARSE_NOENT | parser.XML_PARSE_DTDLOAD
	doc := parser.ReadMemory(string(xmlData), "", "", options)
	defer doc.Free()

	fmt.Fprintf(w, "XML parsed with multiple options")
}
// {/fact}

// bad_case_8 uses encoding/xml with custom entity map including external entities
// {fact rule=xml-external-entity@v1.0 defects=1}
func bad_case_8(w http.ResponseWriter, r *http.Request) {
	xmlData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	decoder := xml.NewDecoder(strings.NewReader(string(xmlData)))
	// ruleid: rule-xml-external-entity
	decoder.Entity = map[string]string{
		"xxe": "file:///etc/passwd",
		"test": "value",
	}
	var result interface{}
	err = decoder.Decode(&result)
	if err != nil {
		http.Error(w, "Failed to parse XML", http.StatusBadRequest)
		return
	}
	fmt.Fprintf(w, "XML parsed with custom entity map")
}
// {/fact}

// bad_case_9 uses XMLParseNoEnt with a file input
// {fact rule=xml-external-entity@v1.0 defects=1}
func bad_case_9() {
	file, err := os.Open("input.xml")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	decoder := xml.NewDecoder(strings.NewReader(string(data)))
	// ruleid: rule-xml-external-entity
	decoder.Entity = xml.HTMLEntity
	var result interface{}
	err = decoder.Decode(&result)
	if err != nil {
		fmt.Println("Error decoding XML:", err)
		return
	}
	fmt.Println("XML parsed successfully from file")
}
// {/fact}

// bad_case_10 uses XMLParseNoEnt with conditional logic
// {fact rule=xml-external-entity@v1.0 defects=1}
func bad_case_10(w http.ResponseWriter, r *http.Request) {
	xmlData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	decoder := xml.NewDecoder(strings.NewReader(string(xmlData)))
	
	allowEntities := r.URL.Query().Get("allowEntities")
	if allowEntities == "true" {
		// ruleid: rule-xml-external-entity
		decoder.Entity = xml.HTMLEntity
	}
	
	var result interface{}
	err = decoder.Decode(&result)
	if err != nil {
		http.Error(w, "Failed to parse XML", http.StatusBadRequest)
		return
	}
	fmt.Fprintf(w, "XML parsed with conditional entity processing")
}
// {/fact}

// bad_case_11 uses XMLParseNoEnt in a function that processes XML from multiple sources
// {fact rule=xml-external-entity@v1.0 defects=1}
func bad_case_11(w http.ResponseWriter, r *http.Request) {
	var xmlData []byte
	var err error
	
	source := r.URL.Query().Get("source")
	if source == "body" {
		xmlData, err = ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}
	} else if source == "file" {
		filename := r.URL.Query().Get("filename")
		xmlData, err = ioutil.ReadFile(filename)
		if err != nil {
			http.Error(w, "Failed to read file", http.StatusBadRequest)
			return
		}
	} else {
		http.Error(w, "Invalid source", http.StatusBadRequest)
		return
	}

	decoder := xml.NewDecoder(strings.NewReader(string(xmlData)))
	// ruleid: rule-xml-external-entity
	decoder.Entity = xml.HTMLEntity
	var result interface{}
	err = decoder.Decode(&result)
	if err != nil {
		http.Error(w, "Failed to parse XML", http.StatusBadRequest)
		return
	}
	fmt.Fprintf(w, "XML parsed from multiple sources")
}
// {/fact}

// bad_case_12 uses XMLParseNoEnt with a wrapper function
func processXML(data []byte) (interface{}, error) {
	decoder := xml.NewDecoder(strings.NewReader(string(data)))
	// ruleid: rule-xml-external-entity
	decoder.Entity = xml.HTMLEntity
	var result interface{}
	err := decoder.Decode(&result)
	return result, err
}

// {fact rule=xml-external-entity@v1.0 defects=1}
func bad_case_12(w http.ResponseWriter, r *http.Request) {
	xmlData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	result, err := processXML(xmlData)
	if err != nil {
		http.Error(w, "Failed to process XML", http.StatusBadRequest)
		return
	}
	fmt.Fprintf(w, "XML processed: %v", result)
}
// {/fact}

// bad_case_13 uses XMLParseNoEnt with a custom reader
// {fact rule=xml-external-entity@v1.0 defects=1}
func bad_case_13(w http.ResponseWriter, r *http.Request) {
	xmlData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	reader := strings.NewReader(string(xmlData))
	limitReader := io.LimitReader(reader, 1024*1024) // Limit to 1MB
	
	decoder := xml.NewDecoder(limitReader)
	// ruleid: rule-xml-external-entity
	decoder.Entity = xml.HTMLEntity
	var result interface{}
	err = decoder.Decode(&result)
	if err != nil {
		http.Error(w, "Failed to parse XML", http.StatusBadRequest)
		return
	}
	fmt.Fprintf(w, "XML parsed with limited reader")
}
// {/fact}

// bad_case_14 uses XMLParseNoEnt with error handling
// {fact rule=xml-external-entity@v1.0 defects=1}
func bad_case_14(w http.ResponseWriter, r *http.Request) {
	xmlData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	decoder := xml.NewDecoder(strings.NewReader(string(xmlData)))
	// ruleid: rule-xml-external-entity
	decoder.Entity = xml.HTMLEntity
	
	var result interface{}
	err = decoder.Decode(&result)
	if err != nil {
		if err == io.EOF {
			http.Error(w, "Empty XML document", http.StatusBadRequest)
		} else if syntaxErr, ok := err.(*xml.SyntaxError); ok {
			http.Error(w, fmt.Sprintf("XML syntax error at offset %d: %s", syntaxErr.Offset, syntaxErr.Error()), http.StatusBadRequest)
		} else {
			http.Error(w, "Failed to parse XML: "+err.Error(), http.StatusBadRequest)
		}
		return
	}
	fmt.Fprintf(w, "XML parsed with detailed error handling")
}
// {/fact}

// bad_case_15 uses XMLParseNoEnt with a complex XML structure
// {fact rule=xml-external-entity@v1.0 defects=1}
func bad_case_15(w http.ResponseWriter, r *http.Request) {
	xmlData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	type Address struct {
		Street  string `xml:"street"`
		City    string `xml:"city"`
		Country string `xml:"country"`
	}
	
	type Person struct {
		Name    string   `xml:"name"`
		Age     int      `xml:"age"`
		Address Address  `xml:"address"`
		Phones  []string `xml:"phone"`
	}
	
	decoder := xml.NewDecoder(strings.NewReader(string(xmlData)))
	// ruleid: rule-xml-external-entity
	decoder.Entity = xml.HTMLEntity
	
	var person Person
	err = decoder.Decode(&person)
	if err != nil {
		http.Error(w, "Failed to parse XML", http.StatusBadRequest)
		return
	}
	fmt.Fprintf(w, "Person parsed: %s, %d years old, from %s", person.Name, person.Age, person.Address.City)
}
// {/fact}

// TRUE NEGATIVES (Secure Code)

// good_case_1 uses encoding/xml without enabling external entities
// {fact rule=xml-external-entity@v1.0 defects=0}
func good_case_1(w http.ResponseWriter, r *http.Request) {
	xmlData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	decoder := xml.NewDecoder(strings.NewReader(string(xmlData)))
	// ok: rule-xml-external-entity
	// No Entity setting, using default which is safe
	var result interface{}
	err = decoder.Decode(&result)
	if err != nil {
		http.Error(w, "Failed to parse XML", http.StatusBadRequest)
		return
	}
	fmt.Fprintf(w, "XML parsed safely")
}
// {/fact}

// good_case_2 uses libxml2 without XML_PARSE_NOENT flag
// {fact rule=xml-external-entity@v1.0 defects=0}
func good_case_2(w http.ResponseWriter, r *http.Request) {
	xmlData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	// ok: rule-xml-external-entity
	doc := parser.ReadMemory(string(xmlData), "", "", 0) // No XML_PARSE_NOENT flag
	defer doc.Free()

	rootElement := doc.RootElement()
	content := rootElement.Content()
	fmt.Fprintf(w, "Parsed XML content safely: %s", content)
}
// {/fact}

// good_case_3 uses libxml2 with safe options
// {fact rule=xml-external-entity@v1.0 defects=0}
func good_case_3(w http.ResponseWriter, r *http.Request) {
	xmlData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	// ok: rule-xml-external-entity
	options := parser.XML_PARSE_RECOVER | parser.XML_PARSE_NOBLANKS // No XML_PARSE_NOENT
	doc := parser.ReadMemory(string(xmlData), "", "", options)
	defer doc.Free()

	fmt.Fprintf(w, "XML parsed with safe options")
}
// {/fact}

// good_case_4 uses xmlquery with disallowXXE set to true
// {fact rule=xml-external-entity@v1.0 defects=0}
func good_case_4(w http.ResponseWriter, r *http.Request) {
	xmlData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	// ok: rule-xml-external-entity
	doc, err := xmlquery.Parse(strings.NewReader(string(xmlData)), xmlquery.ParserOptions{DisallowXXE: true})
	if err != nil {
		http.Error(w, "Failed to parse XML", http.StatusBadRequest)
		return
	}

	result := xmlquery.Find(doc, "//data")
	fmt.Fprintf(w, "Found %d data elements", len(result))
}
// {/fact}

// good_case_5 uses mxj without enabling XMLParseNoEnt
// {fact rule=xml-external-entity@v1.0 defects=0}
func good_case_5(w http.ResponseWriter, r *http.Request) {
	xmlData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	// ok: rule-xml-external-entity
	mxj.SetParseNoEnt(false) // Explicitly disable external entity processing
	m, err := mxj.NewMapXml(xmlData)
	if err != nil {
		http.Error(w, "Failed to parse XML", http.StatusBadRequest)
		return
	}

	fmt.Fprintf(w, "XML safely parsed into map: %v", m)
}
// {/fact}

// good_case_6 uses etree with entity processing disabled
// {fact rule=xml-external-entity@v1.0 defects=0}
func good_case_6(w http.ResponseWriter, r *http.Request) {
	xmlData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	doc := etree.NewDocument()
	// ok: rule-xml-external-entity
	doc.EnableEntityProcessing = false // Explicitly disable entity processing
	err = doc.ReadFromBytes(xmlData)
	if err != nil {
		http.Error(w, "Failed to parse XML", http.StatusBadRequest)
		return
	}

	fmt.Fprintf(w, "XML parsed safely with etree")
}
// {/fact}

// good_case_7 uses libxml2 with safe options in a complex setting
// {fact rule=xml-external-entity@v1.0 defects=0}
func good_case_7(w http.ResponseWriter, r *http.Request) {
	xmlData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	// ok: rule-xml-external-entity
	// Setting multiple options but excluding the dangerous XML_PARSE_NOENT
	options := parser.XML_PARSE_RECOVER | parser.XML_PARSE_NOBLANKS | parser.XML_PARSE_NOERROR
	doc := parser.ReadMemory(string(xmlData), "", "", options)
	defer doc.Free()

	fmt.Fprintf(w, "XML parsed with safe multiple options")
}
// {/fact}

// good_case_8 uses encoding/xml with safe entity map
// {fact rule=xml-external-entity@v1.0 defects=0}
func good_case_8(w http.ResponseWriter, r *http.Request) {
	xmlData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	decoder := xml.NewDecoder(strings.NewReader(string(xmlData)))
	// ok: rule-xml-external-entity
	// Using a custom entity map with only internal entities
	decoder.Entity = map[string]string{
		"nbsp": " ",
		"quot": "\"",
		"apos": "'",
		"lt":   "<",
		"gt":   ">",
	}
	var result interface{}
	err = decoder.Decode(&result)
	if err != nil {
		http.Error(w, "Failed to parse XML", http.StatusBadRequest)
		return
	}
	fmt.Fprintf(w, "XML parsed with safe entity map")
}
// {/fact}

// good_case_9 uses safe XML parsing with a file input
// {fact rule=xml-external-entity@v1.0 defects=0}
func good_case_9() {
	file, err := os.Open("input.xml")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	// ok: rule-xml-external-entity
	decoder := xml.NewDecoder(strings.NewReader(string(data)))
	// Not setting decoder.Entity, which keeps external entity processing disabled
	var result interface{}
	err = decoder.Decode(&result)
	if err != nil {
		fmt.Println("Error decoding XML:", err)
		return
	}
	fmt.Println("XML parsed safely from file")
}
// {/fact}

// good_case_10 uses safe XML parsing with conditional logic
// {fact rule=xml-external-entity@v1.0 defects=0}
func good_case_10(w http.ResponseWriter, r *http.Request) {
	xmlData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	decoder := xml.NewDecoder(strings.NewReader(string(xmlData)))
	
	// ok: rule-xml-external-entity
	// Even with conditional logic, we never enable external entities
	allowEntities := r.URL.Query().Get("allowEntities")
	if allowEntities == "true" {
		// Only set safe entities
		decoder.Entity = map[string]string{
			"nbsp": " ",
			"quot": "\"",
		}
	}
	
	var result interface{}
	err = decoder.Decode(&result)
	if err != nil {
		http.Error(w, "Failed to parse XML", http.StatusBadRequest)
		return
	}
	fmt.Fprintf(w, "XML parsed safely with conditional logic")
}
// {/fact}

// good_case_11 uses safe XML parsing from multiple sources
// {fact rule=xml-external-entity@v1.0 defects=0}
func good_case_11(w http.ResponseWriter, r *http.Request) {
	var xmlData []byte
	var err error
	
	source := r.URL.Query().Get("source")
	if source == "body" {
		xmlData, err = ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}
	} else if source == "file" {
		filename := r.URL.Query().Get("filename")
		xmlData, err = ioutil.ReadFile(filename)
		if err != nil {
			http.Error(w, "Failed to read file", http.StatusBadRequest)
			return
		}
	} else {
		http.Error(w, "Invalid source", http.StatusBadRequest)
		return
	}

	// ok: rule-xml-external-entity
	decoder := xml.NewDecoder(strings.NewReader(string(xmlData)))
	// Not setting decoder.Entity keeps external entity processing disabled
	var result interface{}
	err = decoder.Decode(&result)
	if err != nil {
		http.Error(w, "Failed to parse XML", http.StatusBadRequest)
		return
	}
	fmt.Fprintf(w, "XML parsed safely from multiple sources")
}
// {/fact}

// good_case_12 uses safe XML parsing with a wrapper function
func safeProcessXML(data []byte) (interface{}, error) {
	// ok: rule-xml-external-entity
	decoder := xml.NewDecoder(strings.NewReader(string(data)))
	// Not setting decoder.Entity keeps external entity processing disabled
	var result interface{}
	err := decoder.Decode(&result)
	return result, err
}

// {fact rule=xml-external-entity@v1.0 defects=0}
func good_case_12(w http.ResponseWriter, r *http.Request) {
	xmlData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	result, err := safeProcessXML(xmlData)
	if err != nil {
		http.Error(w, "Failed to process XML", http.StatusBadRequest)
		return
	}
	fmt.Fprintf(w, "XML processed safely: %v", result)
}
// {/fact}

// good_case_13 uses safe XML parsing with a custom reader
// {fact rule=xml-external-entity@v1.0 defects=0}
func good_case_13(w http.ResponseWriter, r *http.Request) {
	xmlData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	reader := strings.NewReader(string(xmlData))
	limitReader := io.LimitReader(reader, 1024*1024) // Limit to 1MB
	
	// ok: rule-xml-external-entity
	decoder := xml.NewDecoder(limitReader)
	// Not setting decoder.Entity keeps external entity processing disabled
	var result interface{}
	err = decoder.Decode(&result)
	if err != nil {
		http.Error(w, "Failed to parse XML", http.StatusBadRequest)
		return
	}
	fmt.Fprintf(w, "XML parsed safely with limited reader")
}
// {/fact}

// good_case_14 uses safe XML parsing with error handling
// {fact rule=xml-external-entity@v1.0 defects=0}
func good_case_14(w http.ResponseWriter, r *http.Request) {
	xmlData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	// ok: rule-xml-external-entity
	decoder := xml.NewDecoder(strings.NewReader(string(xmlData)))
	// Not setting decoder.Entity keeps external entity processing disabled
	
	var result interface{}
	err = decoder.Decode(&result)
	if err != nil {
		if err == io.EOF {
			http.Error(w, "Empty XML document", http.StatusBadRequest)
		} else if syntaxErr, ok := err.(*xml.SyntaxError); ok {
			http.Error(w, fmt.Sprintf("XML syntax error at offset %d: %s", syntaxErr.Offset, syntaxErr.Error()), http.StatusBadRequest)
		} else {
			http.Error(w, "Failed to parse XML: "+err.Error(), http.StatusBadRequest)
		}
		return
	}
	fmt.Fprintf(w, "XML parsed safely with detailed error handling")
}
// {/fact}

// good_case_15 uses safe XML parsing with a complex XML structure
// {fact rule=xml-external-entity@v1.0 defects=0}
func good_case_15(w http.ResponseWriter, r *http.Request) {
	xmlData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	type Address struct {
		Street  string `xml:"street"`
		City    string `xml:"city"`
		Country string `xml:"country"`
	}
	
	type Person struct {
		Name    string   `xml:"name"`
		Age     int      `xml:"age"`
		Address Address  `xml:"address"`
		Phones  []string `xml:"phone"`
	}
	
	// ok: rule-xml-external-entity
	decoder := xml.NewDecoder(strings.NewReader(string(xmlData)))
	// Not setting decoder.Entity keeps external entity processing disabled
	
	var person Person
	err = decoder.Decode(&person)
	if err != nil {
		http.Error(w, "Failed to parse XML", http.StatusBadRequest)
		return
	}
	fmt.Fprintf(w, "Person parsed safely: %s, %d years old, from %s", person.Name, person.Age, person.Address.City)
}
// {/fact}

func main() {
	http.HandleFunc("/bad1", bad_case_1)
	http.HandleFunc("/bad2", bad_case_2)
	http.HandleFunc("/bad3", bad_case_3)
	http.HandleFunc("/bad4", bad_case_4)
	http.HandleFunc("/bad5", bad_case_5)
	http.HandleFunc("/bad6", bad_case_6)
	http.HandleFunc("/bad7", bad_case_7)
	http.HandleFunc("/bad8", bad_case_8)
	http.HandleFunc("/bad10", bad_case_10)
	http.HandleFunc("/bad11", bad_case_11)
	http.HandleFunc("/bad12", bad_case_12)
	http.HandleFunc("/bad13", bad_case_13)
	http.HandleFunc("/bad14", bad_case_14)
	http.HandleFunc("/bad15", bad_case_15)
	
	http.HandleFunc("/good1", good_case_1)
	http.HandleFunc("/good2", good_case_2)
	http.HandleFunc("/good3", good_case_3)
	http.HandleFunc("/good4", good_case_4)
	http.HandleFunc("/good5", good_case_5)
	http.HandleFunc("/good6", good_case_6)
	http.HandleFunc("/good7", good_case_7)
	http.HandleFunc("/good8", good_case_8)
	http.HandleFunc("/good10", good_case_10)
	http.HandleFunc("/good11", good_case_11)
	http.HandleFunc("/good12", good_case_12)
	http.HandleFunc("/good13", good_case_13)
	http.HandleFunc("/good14", good_case_14)
	http.HandleFunc("/good15", good_case_15)
	
	http.ListenAndServe(":8080", nil)
}