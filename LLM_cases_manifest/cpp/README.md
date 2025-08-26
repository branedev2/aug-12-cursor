# CPP LLM Benchmarks

This directory contains LLM benchmark test cases for **cpp** programming language.

## Overview

This collection includes security vulnerability test cases and best practices for cpp development, organized by CWE (Common Weakness Enumeration) categories.

## Structure

- **Test Cases**: 42 cpp files
- **CWE Categories**: 35 different vulnerability categories
- **Coverage**: Security vulnerabilities, coding best practices, and common pitfalls

## Categories Included

- CWE-119
- CWE-120
- CWE-125
- CWE-193
- CWE-197
- CWE-20
- CWE-200
- CWE-22
- CWE-287
- CWE-326
- CWE-330
- CWE-362
- CWE-367
- CWE-377
- CWE-416
- CWE-434
- CWE-467
- CWE-469
- CWE-476
- CWE-478
- CWE-480
- CWE-562
- CWE-676
- CWE-681
- CWE-690
- CWE-732
- CWE-754
- CWE-764
- CWE-77
- CWE-78
- CWE-787
- CWE-79
- CWE-862
- CWE-89
- CWE-94

## Usage

These test cases are designed to:

1. **Train LLM models** on secure coding practices
2. **Benchmark model performance** in identifying security vulnerabilities  
3. **Validate code analysis tools** for cpp
4. **Educational purposes** for secure cpp development

## File Naming Convention

Files follow the pattern: `{category}-{description}_{complexity}.{extension}`

- **category**: CWE identifier or best practice category
- **description**: Brief description of the test case
- **complexity**: basic, intermediate, or advanced

## Contributing

When adding new test cases:

1. Follow the existing file naming convention
2. Include both positive and negative examples
3. Add appropriate comments explaining the vulnerability or best practice
4. Ensure code compiles and runs (where applicable)

## Security Focus Areas

The test cases cover various security domains:

- **Input Validation** (CWE-20, CWE-79, CWE-89)
- **Authentication & Authorization** (CWE-287, CWE-306, CWE-862)
- **Cryptography** (CWE-326, CWE-327, CWE-328)
- **Memory Management** (CWE-119, CWE-125, CWE-416)
- **Error Handling** (CWE-209, CWE-252, CWE-754)
- **And many more...**

---

*Part of the AWS Guru LLM Benchmarks project for improving AI-assisted secure coding.*
