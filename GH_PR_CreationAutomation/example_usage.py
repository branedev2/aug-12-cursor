#!/usr/bin/env python3
"""
Example usage of the PR automation script
"""

from pr_automation import PRAutomation

def example_usage():
    """Example of how to use the PRAutomation class"""
    
    # Configuration
    github_token = ""  # Replace with your actual token
    repo_url = "https://github.com/branedev2/aug-12-cursor.git"  # Replace with your repo
    input_folder = "/Users/branedev/Documents/pr_raise_auto/pr_auto/src/AWSGuruInternalHelperTools/src/aws_guru_internal_helper_tools/GH_PR_CreationAutomation/AWSGuruGolangSamples/src/golang/go_detectors_devashish"  # Path to folder containing source files
    
    # Create automation instance with batch size of 5
    automation = PRAutomation(github_token, repo_url, input_folder, batch_size=5)
    
    # Run the automation
    pr_urls = automation.run()
    
    # Print results
    print(f"Created {len(pr_urls)} pull requests:")
    for url in pr_urls:
        print(f"  - {url}")

if __name__ == "__main__":
    example_usage()