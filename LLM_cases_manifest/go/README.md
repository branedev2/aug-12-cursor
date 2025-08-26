# GO LLM Benchmarks

This directory contains LLM benchmark test cases for **go** programming language.

## Overview

This collection includes security vulnerability test cases and best practices for go development, organized by CWE (Common Weakness Enumeration) categories.

## Structure

- **Test Cases**: 76 go files
- **CWE Categories**: 44 different vulnerability categories
- **Coverage**: Security vulnerabilities, coding best practices, and common pitfalls

## Categories Included

- Best_Practices
- CWE-1004
- CWE-117
- CWE-19
- CWE-190
- CWE-200
- CWE-22
- CWE-23
- CWE-276
- CWE-287
- CWE-289
- CWE-295
- CWE-300
- CWE-306
- CWE-310
- CWE-319
- CWE-322
- CWE-326
- CWE-327
- CWE-338
- CWE-345
- CWE-352
- CWE-362
- CWE-378
- CWE-409
- CWE-426
- CWE-470
- CWE-476
- CWE-477
- CWE-489
- CWE-502
- CWE-548
- CWE-611
- CWE-614
- CWE-664
- CWE-77
- CWE-78
- CWE-79
- CWE-798
- CWE-863
- CWE-89
- CWE-913
- CWE-918
- CWE-94
- CWE-95

## Usage

These test cases are designed to:

1. **Train LLM models** on secure coding practices
2. **Benchmark model performance** in identifying security vulnerabilities  
3. **Validate code analysis tools** for go
4. **Educational purposes** for secure go development

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
