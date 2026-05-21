import requests
import time

# --- CONFIGURATION ---
CLIENT_ID = ""
CLIENT_SECRET = ""
TARGET_DOMAIN = "domainname.com"

# --- AUTHENTICATION ---
def get_bearer_token(client_id, client_secret):
    """Generates an OAuth2 access token for Cisco Umbrella API."""
    url = "https://api.umbrella.com/auth/v2/token"
    try:
        response = requests.post(url, auth=(client_id, client_secret), data={"grant_type": "client_credentials"})
        response.raise_for_status()
        return response.json().get("access_token")
    except requests.exceptions.RequestException as e:
        print(f"Error fetching auth token: {e}")
        return None

# --- REPORTING API SEARCH ---
def check_domain_activity(token, domain):
    """Queries the Reporting API for recent DNS activity matching the domain."""
    url = "https://api.umbrella.com/reports/v2/activity/dns"
    headers = {"Authorization": f"Bearer {token}"}
    # Look for traffic within the last 24 hours
    params = {
        "q": domain,
        "from": int((time.time() - 86400) * 1000), 
        "to": int(time.time() * 1000),
        "limit": 10
    }
    
    print(f"\nSearching activity logs for: {domain}...")
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        data = response.json().get("requests", [])
        if data:
            print(f"[!] Found {len(data)} recent security event(s)/query log(s):")
            for record in data:
                print(f"    - Time: {record.get('timestamp')} | Identity: {record.get('identityName')} | Action: {record.get('allowed')}")
        else:
            print("[-] No recent matching domain traffic found in reporting logs.")
    else:
        print(f"[-] Reporting API returned status code: {response.status_code}")

# --- POLICIES API (DESTINATION LISTS) MATCHING ---
def scan_destination_lists(token, domain):
    """Fetches all destination lists and inspects each for the target domain."""
    headers = {"Authorization": f"Bearer {token}"}
    lists_url = "https://api.umbrella.com/policies/v2/destinationlists"
    
    print(f"\nScanning destination lists for configurations containing: {domain}...")
    response = requests.get(lists_url, headers=headers)
    
    if response.status_code != 200:
        print(f"[-] Failed to fetch destination lists: {response.status_code}")
        return

    lists = response.json().get("data", [])
    matched_lists = []

    for d_list in lists:
        list_id = d_list.get("id")
        list_name = d_list.get("name")
        list_type = d_list.get("access") # Blocked, Allowed, etc.
        
        # Paginate or fetch destinations inside this specific list
        dest_url = f"https://api.umbrella.com/policies/v2/destinationlists/{list_id}/destinations"
        dest_response = requests.get(dest_url, headers=headers)
        
        if dest_response.status_code == 200:
            destinations = dest_response.json().get("data", [])
            for dest in destinations:
                # Umbrella treats subdomains implicitly or explicitly depending on input format
                if domain.lower() in dest.get("destination", "").lower():
                    matched_lists.append({
                        "name": list_name,
                        "id": list_id,
                        "type": list_type,
                        "entry": dest.get("destination")
                    })
                    
    if matched_lists:
        print(f"[!] Domain configuration found in the following lists:")
        for match in matched_lists:
            print(f"    - List: '{match['name']}' (ID: {match['id']}) | Type: {match['type']} | Configured Entry: {match['entry']}")
    else:
        print("[-] Domain not found in any existing Block or Allow destination lists.")

# --- MAIN EXECUTION ---
def main():
    token = get_bearer_token(CLIENT_ID, CLIENT_SECRET)
    if not token:
        print("Authentication failed. Exiting.")
        return
        
    # Run the report log check
    check_domain_activity(token, TARGET_DOMAIN)
    
    # Run the policy destination check
    scan_destination_lists(token, TARGET_DOMAIN)

if __name__ == "__main__":
    main()
