# SCALA LLM Benchmarks

This directory contains LLM benchmark test cases for **scala** programming language.

## Overview

This collection includes security vulnerability test cases and best practices for scala development, organized by CWE (Common Weakness Enumeration) categories.

## Structure

- **Test Cases**: 67 scala files
- **CWE Categories**: 43 different vulnerability categories
- **Coverage**: Security vulnerabilities, coding best practices, and common pitfalls

## Categories Included

- CWE-1004
- CWE-113
- CWE-117
- CWE-129
- CWE-134
- CWE-176
- CWE-190
- CWE-20
- CWE-22
- CWE-259
- CWE-287
- CWE-295
- CWE-296
- CWE-297
- CWE-319
- CWE-326
- CWE-327
- CWE-328
- CWE-330
- CWE-352
- CWE-501
- CWE-502
- CWE-522
- CWE-539
- CWE-552
- CWE-601
- CWE-611
- CWE-614
- CWE-732
- CWE-77
- CWE-78
- CWE-780
- CWE-79
- CWE-798
- CWE-88
- CWE-89
- CWE-90
- CWE-917
- CWE-918
- CWE-93
- CWE-94
- CWE-942
- CWE-943

## Usage

These test cases are designed to:

1. **Train LLM models** on secure coding practices
2. **Benchmark model performance** in identifying security vulnerabilities  
3. **Validate code analysis tools** for scala
4. **Educational purposes** for secure scala development

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
