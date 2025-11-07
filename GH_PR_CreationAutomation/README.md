# GitHub PR Creation Automation

Automates creating pull requests by grouping source files into batches of 5 and creating separate PRs for each batch.

## Setup

```bash
pip install PyGithub
```

## Usage

```bash
python pr_automation.py <github_token> <repo_url> <source_folder> [batch_size]
```

**Examples:**
```bash
# Default batch size (5 files per PR)
python pr_automation.py ghp_xxx https://github.com/user/repo.git ./MyJavaTests

# Custom batch sizes
python pr_automation.py ghp_xxx https://github.com/user/repo.git ./PythonScripts 3
python pr_automation.py ghp_xxx https://github.com/user/repo.git ./JS-Components 10
python pr_automation.py ghp_xxx https://github.com/user/repo.git ./GoCode 1
```

## Features

- **Language Detection**: Auto-detects from folder name (java, python, javascript, etc.)
- **Configurable Batching**: Groups files into customizable batches (default: 5)
- **Recursive Search**: Finds files in nested folders
- **Idempotent**: Safe to re-run
- **Professional PRs**: Descriptive titles and descriptions with source folder names

## Supported Languages

Java, Python, JavaScript, TypeScript, C++, C, C#, Go, Rust, PHP, Ruby, Swift, Kotlin

## What It Does

1. Scans folder recursively for source files
2. Groups files into configurable batches (default: 5)
3. For each batch:
   - Creates branch: `feature/myjava-tests-java-batch-01`
   - Commits: `feat: add Java files from MyJavaTests - batch 01`
   - Creates PR: `Add Java Files from MyJavaTests - Batch 01`

## Batch Size Options

- **Small batches** (1-3): More PRs, easier individual review
- **Medium batches** (5-7): Balanced approach (default: 5)
- **Large batches** (10+): Fewer PRs, bulk processing

## Output Example

```
Detected language: java
Looking for files: *.java
Batch size: 5 files per PR
Found 12 java files (batch size: 5)
Created myjava-tests-java-batch-01 with 5 files
Created myjava-tests-java-batch-02 with 5 files
Created myjava-tests-java-batch-03 with 2 files

=== Summary ===
Language: Java
Created/Found 3 pull requests:
  - https://github.com/user/repo/pull/123
  - https://github.com/user/repo/pull/124
  - https://github.com/user/repo/pull/125
```