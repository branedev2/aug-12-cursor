#!/usr/bin/env python3
"""
GitHub PR Creation Automation Script

This script automates the process of creating pull requests for multiple subfolders
by cloning a repo, creating branches, copying files, and creating PRs.
"""

import os
import sys
import subprocess
import shutil
import tempfile
import json
from datetime import datetime
from pathlib import Path
from github import Github
from github.GithubException import GithubException


class PRAutomation:
    def __init__(self, github_token, repo_url, input_folder, batch_size=5):
        self.github_token = github_token
        self.repo_url = repo_url
        self.input_folder = Path(input_folder)
        self.batch_size = batch_size
        self.github_client = Github(github_token)
        self.temp_dir = None
        self.repo_name = self._extract_repo_name()
        self.github_repo = self.github_client.get_repo(self.repo_name)
        self.grouped_folders_dir = None
        self.pr_data = []
    

        
    def _extract_repo_name(self):
        """Extract owner/repo from GitHub URL"""
        if self.repo_url.endswith('.git'):
            url = self.repo_url[:-4]
        else:
            url = self.repo_url
        return '/'.join(url.split('/')[-2:])
    
    def _run_git_command(self, cmd, cwd=None):
        """Execute git command and return result"""
        try:
            result = subprocess.run(
                cmd, shell=True, cwd=cwd, capture_output=True, text=True, check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            print(f"Git command failed: {cmd}")
            print(f"Error: {e.stderr}")
            raise
    
    def clone_repo(self):
        """Clone the repository to a temporary directory"""
        self.temp_dir = tempfile.mkdtemp()
        print(f"Cloning repo to: {self.temp_dir}")
        self._run_git_command(f"git clone {self.repo_url} repo", cwd=self.temp_dir)
        return os.path.join(self.temp_dir, "repo")
    
    def create_branch(self, branch_name, repo_path):
        """Create and checkout a new branch"""
        try:
            # Switch to main first
            self._run_git_command("git checkout main", cwd=repo_path)
            self._run_git_command("git pull origin main", cwd=repo_path)
            
            # Check if branch already exists locally
            try:
                subprocess.run(f"git checkout {branch_name}", shell=True, cwd=repo_path, capture_output=True, check=True)
                print(f"Branch {branch_name} already exists locally, using it")
                return True
            except subprocess.CalledProcessError:
                # Branch doesn't exist, create it
                self._run_git_command(f"git checkout -b {branch_name}", cwd=repo_path)
                print(f"Created new branch: {branch_name}")
                return False
                
        except subprocess.CalledProcessError as e:
            print(f"Failed to create/checkout branch {branch_name}: {e}")
            raise
    
    def copy_files(self, subfolder_path, repo_path):
        """Copy files from subfolder to repo, maintaining structure"""
        print(f"Copying files from {subfolder_path} to {repo_path}")
        
        for item in subfolder_path.iterdir():
            dest_path = Path(repo_path) / item.name
            
            if item.is_file():
                shutil.copy2(item, dest_path)
            elif item.is_dir():
                if dest_path.exists():
                    shutil.rmtree(dest_path)
                shutil.copytree(item, dest_path)
    
    def commit_and_push(self, branch_name, subfolder_name, repo_path):
        """Stage, commit, and push changes"""
        # Check if there are any changes
        try:
            status = self._run_git_command("git status --porcelain", cwd=repo_path)
            if not status:
                print("No changes to commit")
                return False
        except subprocess.CalledProcessError:
            pass
        
        # Stage all changes
        self._run_git_command("git add .", cwd=repo_path)
        
        # Commit changes with descriptive message including folder name
        batch_num = subfolder_name.split('-')[-1] if 'batch' in subfolder_name else subfolder_name
        folder_name = self.input_folder.name
        commit_msg = f"feat: add files from {folder_name} - batch {batch_num}"
        self._run_git_command(f'git commit -m "{commit_msg}"', cwd=repo_path)
        
        # Push to remote
        try:
            self._run_git_command(f"git push origin {branch_name}", cwd=repo_path)
            print(f"Pushed branch {branch_name} to remote")
            return True
        except subprocess.CalledProcessError as e:
            if "already up-to-date" in e.stderr.lower():
                print(f"Branch {branch_name} is already up-to-date")
                return True
            raise
    
    def create_pull_request(self, branch_name, subfolder_name):
        """Create a pull request using GitHub API"""
        try:
            # Check if PR already exists
            existing_prs = list(self.github_repo.get_pulls(
                state='open', head=f"{self.github_repo.owner.login}:{branch_name}"
            ))
            
            if existing_prs:
                pr_url = existing_prs[0].html_url
                print(f"PR already exists: {pr_url}")
                return pr_url
            
            # Create descriptive PR title and body with folder name
            batch_num = subfolder_name.split('-')[-1] if 'batch' in subfolder_name else subfolder_name
            folder_name = self.input_folder.name
            pr_title = f"Add Files from {folder_name} - Batch {batch_num}"
            pr_body = f"""## 📝 Description
This PR adds a batch of files from the `{folder_name}` directory to the repository.

## 📁 Files Added
- Source Folder: `{folder_name}`
- Batch: {subfolder_name}
- Contains files collected from the source directory

## 🔍 Changes
- Added files from `{folder_name}` maintaining original directory structure
- Files organized in batch {batch_num} for easier review
- Ready for integration and testing

## 💾 Source
Original files sourced from: `{folder_name}`
"""
            
            pr = self.github_repo.create_pull(
                title=pr_title,
                body=pr_body,
                head=branch_name,
                base="main"
            )
            
            pr_url = pr.html_url
            print(f"Created PR: {pr_url}")
            return pr_url
            
        except GithubException as e:
            if e.status == 422 and "already exists" in str(e):
                print(f"PR for branch {branch_name} already exists")
                # Try to find the existing PR
                prs = list(self.github_repo.get_pulls(state='open', head=branch_name))
                if prs:
                    return prs[0].html_url
            else:
                print(f"Failed to create PR: {e}")
                raise
    
    def process_subfolder(self, subfolder, repo_path):
        """Process a single subfolder: create branch, copy files, commit, push, create PR"""
        subfolder_name = subfolder.name
        branch_name = f"feature/{subfolder_name}"
        
        print(f"\n--- Processing batch: {subfolder_name} ---")
        
        try:
            # Create and checkout branch
            branch_existed = self.create_branch(branch_name, repo_path)
            
            # Copy files from subfolder to repo
            self.copy_files(subfolder, repo_path)
            
            # Commit and push changes
            has_changes = self.commit_and_push(branch_name, subfolder_name, repo_path)
            
            if has_changes or branch_existed:
                # Create pull request
                pr_url = self.create_pull_request(branch_name, subfolder_name)
                return pr_url
            else:
                print("No changes to create PR for")
                return None
                
        except Exception as e:
            print(f"Error processing {subfolder_name}: {e}")
            return None
    
    def create_grouped_folders(self):
        """Create subfolders with configurable batch size"""
        if not self.input_folder.exists():
            print(f"Input folder does not exist: {self.input_folder}")
            return []
        
        # Get all files recursively
        source_files = [f for f in self.input_folder.rglob('*') if f.is_file()]
        if not source_files:
            print(f"No files found in: {self.input_folder}")
            return []
        
        print(f"Found {len(source_files)} files (batch size: {self.batch_size})")
        
        # Create temporary directory for grouped folders
        self.grouped_folders_dir = tempfile.mkdtemp(prefix="file_groups_")
        subfolders = []
        
        # Group files into chunks of specified batch size
        folder_name = self.input_folder.name.lower().replace(' ', '-').replace('_', '-')
        for i in range(0, len(source_files), self.batch_size):
            group_files = source_files[i:i+self.batch_size]
            batch_num = (i // self.batch_size) + 1
            subfolder_name = f"{folder_name}-batch-{batch_num:02d}"
            subfolder_path = Path(self.grouped_folders_dir) / subfolder_name
            
            # Create subfolder
            subfolder_path.mkdir()
            
            # Copy files to subfolder, maintaining relative structure
            for source_file in group_files:
                # Get relative path from input folder
                rel_path = source_file.relative_to(self.input_folder)
                dest_path = subfolder_path / rel_path
                
                # Create parent directories if needed
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source_file, dest_path)
            
            subfolders.append(subfolder_path)
            print(f"Created {subfolder_name} with {len(group_files)} files")
        
        return subfolders
    
    def save_pr_data_json(self, pr_urls):
        """Save PR data to JSON file"""
        # Create PR_data_json_store directory
        json_dir = Path("PR_data_json_store")
        json_dir.mkdir(exist_ok=True)
        
        # Create JSON data
        folder_name = self.input_folder.name
        json_data = {
            "folder_name": folder_name,

            "total_prs": len(pr_urls),
            "timestamp": datetime.now().isoformat(),
            "source_folder_path": str(self.input_folder),
            "repository": self.repo_name,
            "pull_requests": pr_urls
        }
        
        # Save to JSON file
        json_file = json_dir / f"{folder_name}.json"
        with open(json_file, 'w') as f:
            json.dump(json_data, f, indent=2)
        
        print(f"Saved PR data to: {json_file}")
    
    def run(self):
        """Main execution method"""
        # Create grouped subfolders from files
        subfolders = self.create_grouped_folders()
        if not subfolders:
            return []
        
        # Clone repository
        repo_path = self.clone_repo()
        pr_urls = []
        
        try:
            # Process each subfolder
            for subfolder in subfolders:
                pr_url = self.process_subfolder(subfolder, repo_path)
                if pr_url:
                    pr_urls.append(pr_url)
                
                # Switch back to main for next iteration
                self._run_git_command("git checkout main", cwd=repo_path)
            
            # Save PR data to JSON
            if pr_urls:
                self.save_pr_data_json(pr_urls)
            
            return pr_urls
            
        finally:
            # Cleanup temporary directories
            if self.temp_dir and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
                print(f"Cleaned up temporary directory: {self.temp_dir}")
            
            if self.grouped_folders_dir and os.path.exists(self.grouped_folders_dir):
                shutil.rmtree(self.grouped_folders_dir)
                print(f"Cleaned up grouped folders directory: {self.grouped_folders_dir}")


def main():
    """Main function to run the PR automation"""
    if len(sys.argv) < 4 or len(sys.argv) > 5:
        print("Usage: python pr_automation.py <github_token> <repo_url> <source_folder> [batch_size]")
        print("Example: python pr_automation.py ghp_xxx https://github.com/user/repo.git ./MyJavaTests")
        print("Example: python pr_automation.py ghp_xxx https://github.com/user/repo.git ./MyJavaTests 3")
        print("      batch_size defaults to 5 files per PR if not specified")
        sys.exit(1)
    
    github_token = sys.argv[1]
    repo_url = sys.argv[2]
    language_folder = sys.argv[3]
    batch_size = int(sys.argv[4]) if len(sys.argv) == 5 else 5
    
    # Validate inputs
    if not os.path.exists(language_folder):
        print(f"Error: Source folder does not exist: {language_folder}")
        sys.exit(1)
    
    if batch_size < 1:
        print(f"Error: Batch size must be at least 1, got: {batch_size}")
        sys.exit(1)
    
    try:
        # Create and run automation
        automation = PRAutomation(github_token, repo_url, language_folder, batch_size)
        print(f"Batch size: {batch_size} files per PR")
        pr_urls = automation.run()
        
        # Print summary
        print(f"\n=== Summary ===")
        print(f"\n=== Summary ===")

        print(f"Created/Found {len(pr_urls)} pull requests:")
        for url in pr_urls:
            print(f"  - {url}")
            
    except Exception as e:
        print(f"Script failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()