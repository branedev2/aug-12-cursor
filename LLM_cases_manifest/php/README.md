# PHP LLM Benchmarks

This directory contains LLM benchmark test cases for **php** programming language.

## Overview

This collection includes security vulnerability test cases and best practices for php development, organized by CWE (Common Weakness Enumeration) categories.

## Structure

- **Test Cases**: 75 php files
- **CWE Categories**: 39 different vulnerability categories
- **Coverage**: Security vulnerabilities, coding best practices, and common pitfalls

## Categories Included

- CWE-1004
- CWE-117
- CWE-1275
- CWE-16
- CWE-190
- CWE-200
- CWE-22
- CWE-266
- CWE-283
- CWE-284
- CWE-285
- CWE-287
- CWE-319
- CWE-327
- CWE-328
- CWE-329
- CWE-338
- CWE-346
- CWE-35
- CWE-352
- CWE-409
- CWE-434
- CWE-470
- CWE-502
- CWE-601
- CWE-614
- CWE-73
- CWE-732
- CWE-78
- CWE-79
- CWE-798
- CWE-862
- CWE-89
- CWE-915
- CWE-918
- CWE-94
- CWE-943
- CWE-95
- CWE-98

## Usage

These test cases are designed to:

1. **Train LLM models** on secure coding practices
2. **Benchmark model performance** in identifying security vulnerabilities  
3. **Validate code analysis tools** for php
4. **Educational purposes** for secure php development

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
