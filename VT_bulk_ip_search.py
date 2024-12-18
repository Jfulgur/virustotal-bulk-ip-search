import requests
import time
import csv

# VirusTotal API key
VIRUS_TOTAL_API_KEY = '629b6884ab1b6b7814fa815500dcf575a3e2eede5a089b311982563f748af4a4'
VIRUS_TOTAL_URL = 'https://www.virustotal.com/api/v3/ip_addresses/'

# Headers for VirusTotal API requests
headers = {'x-apikey': VIRUS_TOTAL_API_KEY}

# Function to get the VirusTotal report for an IP address
def get_virustotal_report(ip_address):
    """Fetch the VirusTotal report for an IP address."""
    url = f"{VIRUS_TOTAL_URL}{ip_address}"
    try:
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 429:  # Rate limit exceeded
            reset_time = int(response.headers.get('X-RateLimit-Reset', time.time() + 60))
            sleep_time = reset_time - time.time() + 1  # wait until rate limit reset
            print(f"Rate limit exceeded. Waiting for {sleep_time} seconds.")
            time.sleep(sleep_time)
            return get_virustotal_report(ip_address)  # Retry after sleep
        else:
            print(f"Error {response.status_code}: {response.text}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Request failed for {ip_address}: {e}")
        return None

def read_ips_from_file(file_name):
    """Read IPs from a text file, each IP on a new line."""
    try:
        with open(file_name, 'r') as file:
            ips = [line.strip() for line in file.readlines() if line.strip()]
        return ips
    except FileNotFoundError:
        print(f"File {file_name} not found.")
        return []

def search_bulk_ips(ip_list):
    """Process a list of IPs and retrieve VirusTotal reports including country and owner information."""
    results = []
    
    for ip in ip_list:
        print(f"Fetching reports for {ip}...")
        
        # Get the VirusTotal report for the IP
        vt_report = get_virustotal_report(ip)
        
        if vt_report:
            # Extract VirusTotal data
            vt_hits = vt_report.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
            
            # Extract additional information: country and owner
            country = vt_report.get('data', {}).get('attributes', {}).get('country', 'Unknown')
            owner = vt_report.get('data', {}).get('attributes', {}).get('as_owner', 'Unknown')
            
            # VirusTotal link
            vt_link = f"https://www.virustotal.com/gui/ip-address/{ip}"
            
            # Add combined result to the list with VT link at the end
            results.append([ip, vt_hits, owner, country, vt_link])
        
        # Add a slight delay to respect the rate limits
        time.sleep(15)  # 15 seconds between requests to respect VirusTotal's free tier limits
    
    return results

def save_results_to_csv(results, filename='virustotal_results.csv'):
    """Save the results to a CSV file."""
    with open(filename, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['IP Address', 'Malicious Hits', 'Owner', 'Country', 'VirusTotal Link'])
        writer.writerows(results)
    
    print(f"Results saved to {filename}")

# Main function to execute the script
if __name__ == "__main__":
    # Read IPs from the 'ips.txt' file
    ip_list = read_ips_from_file('ips.txt')
    
    if ip_list:
        # Search VirusTotal and get results
        results = search_bulk_ips(ip_list)
        
        # Save results to a CSV file
        save_results_to_csv(results)
    else:
        print("No IP addresses to process.")
