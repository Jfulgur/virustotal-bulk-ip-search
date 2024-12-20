import requests
import csv
import time

# Replace with your API Keys
VIRUS_TOTAL_API_KEY = '629b6884ab1b6b7814fa815500dcf575a3e2eede5a089b311982563f748af4a4'
ABUSE_IPDB_API_KEY = '5a31e3bdd50fa773ee132c3519e1e0429d6075eea5b432e53699ad70f16ca6f7d64bcff846f1dea6'

# Base URLs for the APIs
VIRUS_TOTAL_URL = 'https://www.virustotal.com/api/v3/ip_addresses/'
ABUSE_IPDB_URL = 'https://api.abuseipdb.com/api/v2/check'

# Set up headers for the API requests
vt_headers = {
    'x-apikey': VIRUS_TOTAL_API_KEY
}

abuse_headers = {
    'Key': ABUSE_IPDB_API_KEY
}

def get_virustotal_report(ip_address):
    """Fetches the VirusTotal report for an IP address."""
    url = f"{VIRUS_TOTAL_URL}{ip_address}"
    response = requests.get(url, headers=vt_headers)
    
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 403:
        print(f"Access forbidden: Invalid VirusTotal API key.")
        return None
    elif response.status_code == 404:
        print(f"IP {ip_address} not found in VirusTotal.")
        return None
    else:
        print(f"Error {response.status_code}: {response.text}")
        return None

def get_abuseipdb_report(ip_address):
    """Fetches the AbuseIPDB report for an IP address."""
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': 90  # Check for reports in the last 90 days
    }
    response = requests.get(ABUSE_IPDB_URL, headers=abuse_headers, params=params)
    
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 403:
        print(f"Access forbidden: Invalid AbuseIPDB API key.")
        return None
    elif response.status_code == 404:
        print(f"IP {ip_address} not found in AbuseIPDB.")
        return None
    else:
        print(f"Error {response.status_code}: {response.text}")
        return None

def search_bulk_ips(ip_list):
    """Process a list of IPs and retrieve both VirusTotal and AbuseIPDB reports."""
    results = []
    for ip in ip_list:
        print(f"Fetching reports for {ip}...")
        
        vt_report = get_virustotal_report(ip)
        abuse_report = get_abuseipdb_report(ip)
        
        if vt_report and abuse_report:
            # Extract VirusTotal data
            vt_hits = vt_report.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
            vt_link = f"https://www.virustotal.com/gui/ip-address/{ip}"
            
            # Extract AbuseIPDB data
            abuse_confidence = abuse_report.get('data', {}).get('abuseConfidenceScore', 0)
            abuse_isp = abuse_report.get('data', {}).get('isp', 'Unknown')
            abuse_country = abuse_report.get('data', {}).get('countryCode', 'Unknown')
            
            # Add combined result to the list
            results.append([ip, vt_hits, vt_link, abuse_confidence, abuse_isp, abuse_country])
        
        time.sleep(60)  # Pause to respect rate limits of API
        
    return results

def save_reports_to_csv(results, filename='combined_ip_reports.csv'):
    """Save the results to a CSV file."""
    with open(filename, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        # Write the header row
        writer.writerow(['IP Address', 'VirusTotal Hits', 'VirusTotal Link', 'AbuseIPDB Confidence', 'AbuseIPDB ISP', 'AbuseIPDB Country'])
        # Write the result rows
        writer.writerows(results)
    print(f"Reports saved to {filename}")

def load_ips_from_file(filename='ips.txt'):
    """Read IPs from a text file, one IP per line."""
    with open(filename, 'r') as file:
        ips = [line.strip() for line in file.readlines() if line.strip()]
    return ips

# Load IPs from a text file
ips_to_search = load_ips_from_file('ips.txt')

# Fetch the results
reports = search_bulk_ips(ips_to_search)

# Save the results to a CSV file
save_reports_to_csv(reports)