# virustotal-bulk-ip-search


# VirusTotal IP Check Scripts

This repository contains Python scripts to check the status of IP addresses using the VirusTotal API.

## Prerequisites

- A GitHub account
- Access to [GitHub Codespaces](https://github.com/codespaces)
- A VirusTotal API key

## Getting Started in GitHub Codespaces

1. Fork or clone this repository to your GitHub account.
2. Open the repository in GitHub Codespaces.
3. Install the required dependencies:
   - Open a terminal in Codespace and run:
     ```bash
     pip install -r requirements.txt
     ```
4. Put your IP addresses in the `ips.txt` file, each on a new line.


## Customizing API Keys

To use the VirusTotal API, you need an API key. You can set your key in the script, or you can use an environment variable.

within the python script input your VT API within this line:
VIRUS_TOTAL_API_KEY = 'your_api_key_here'

Same steps for AbuseIPdb
--------------------------------------------------------------------

## Run the script:
This is how to run the python scripts:
python virustotal_script.py


## Note
- For the VirusTotal bulk IP search, there are 15 seconds delay which is needed so that you would not reach the API rate limiting for a free account.
- For AbuseIPdb scripts, there are 60 seconds delay which is needed so that you would not reach the API rate limiting for a free account.

This means the script will run 1 IP per 15 secons for VT, and 1 IP per 1 min for AbuseIPdb.





