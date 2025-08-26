# PYTHON LLM Benchmarks

This directory contains LLM benchmark test cases for **python** programming language.

## Overview

This collection includes security vulnerability test cases and best practices for python development, organized by CWE (Common Weakness Enumeration) categories.

## Structure

- **Test Cases**: 89 python files
- **CWE Categories**: 25 different vulnerability categories
- **Coverage**: Security vulnerabilities, coding best practices, and common pitfalls

## Categories Included

- Best_Practices
- CWE-117
- CWE-20
- CWE-222
- CWE-223
- CWE-276
- CWE-284
- CWE-285
- CWE-306
- CWE-311
- CWE-319
- CWE-358
- CWE-399
- CWE-502
- CWE-521
- CWE-522
- CWE-602
- CWE-665
- CWE-668
- CWE-710
- CWE-778
- CWE-79
- CWE-798
- CWE-863
- CWE-89
- CWE-943

## Usage

These test cases are designed to:

1. **Train LLM models** on secure coding practices
2. **Benchmark model performance** in identifying security vulnerabilities  
3. **Validate code analysis tools** for python
4. **Educational purposes** for secure python development

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
