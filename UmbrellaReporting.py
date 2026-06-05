#!/usr/bin/env python3
"""
UmbrellaReporting.py
1. Queries DNS activity logs using your exact working Postman URL configuration.
2. Scans all Policy Destination Lists to see if the domain is explicitly configured.
"""

import sys
import requests

# ==================== CONFIGURATION BLOCK ====================
# Paste your Cisco Umbrella API Client ID and Secret here for testing
UMBRELLA_CLIENT_ID = ""
UMBRELLA_CLIENT_SECRET = ""
# =============================================================

def get_access_token(client_id, client_secret):
    """Exchanges Client Credentials for a temporary OAuth2 Bearer token."""
    token_url = "https://api.umbrella.com/auth/v2/token"
    
    if "YOUR_UMBRELLA_" in client_id or "YOUR_UMBRELLA_" in client_secret:
        print("[!] Error: Please update the CONFIGURATION BLOCK with your real API keys.")
        sys.exit(1)
        
    try:
        response = requests.post(
            token_url,
            auth=(client_id, client_secret),
            data={"grant_type": "client_credentials"}
        )
        response.raise_for_status()
        return response.json().get("access_token")
    except requests.exceptions.RequestException as e:
        print(f"[-] Authentication failed: {e}")
        return None
def query_dns_activity(token, target_domain):
    """Queries DNS activity logs using your exact working Postman URL string."""
    url = f"https://api.umbrella.com/reports/v2/activity/dns?domains={target_domain}&from=-30days&to=now&limit=20"
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"
    }
    
    print(f"\n[*] Executing Reporting Query for: '{target_domain}'...")
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        raw_data = response.json()
        
        # THE FIX: Umbrella API v2 stores the records in the "data" array, not "requests"
        data = raw_data.get("data", [])
        
        if data:
            print(f"[+] Found {len(data)} recent query log(s):")
            for record in data:
                # 1. Robust action/verdict extraction
                if "verdict" in record:
                    action = str(record["verdict"]).capitalize()
                elif "allowed" in record:
                    action = "Allowed" if record["allowed"] else "Blocked"
                elif "action" in record:
                    action = str(record["action"]).capitalize()
                else:
                    action = "Unknown"
                
                # 2. Robust identity extraction (Umbrella sometimes uses nested arrays)
                identity = "Unknown Identity"
                if "identityName" in record:
                    identity = record["identityName"]
                elif "identities" in record and isinstance(record["identities"], list) and len(record["identities"]) > 0:
                    identity = record["identities"][0].get("label", "Unknown")
                
                # 3. Clean up the timestamp
                raw_time = str(record.get("timestamp", "N/A"))
                clean_time = raw_time.replace("T", " ")[:19] if raw_time != "N/A" else raw_time
                
                print(f"    - Action: {action: <7} | Identity: {identity} | Time: {clean_time}")
        else:
            print("[-] No matching domain traffic found in reporting logs for the last 30 days.")
            # Safety net: prints the root keys returned so you can see if "data" is missing
            print(f"    [Debug] API returned these keys: {list(raw_data.keys())}")
            
    except requests.exceptions.RequestException as e:
        print(f"[-] Reporting API request failed: {e}")

def scan_destination_lists(token, target_domain):
    """Fetches all existing destination lists and checks if the domain is inside them."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"
    }
    lists_url = "https://api.umbrella.com/policies/v2/destinationlists"
    
    print(f"\n[*] Scanning Destination Lists for configurations matching: '{target_domain}'...")
    
    try:
        response = requests.get(lists_url, headers=headers)
        response.raise_for_status()
        lists = response.json().get("data", [])
        matched_lists = []

        for d_list in lists:
            list_id = d_list.get("id")
            list_name = d_list.get("name")
            list_type = d_list.get("access") 
            
            # Fetch destinations inside this specific list
            dest_url = f"https://api.umbrella.com/policies/v2/destinationlists/{list_id}/destinations"
            dest_response = requests.get(dest_url, headers=headers)
            
            if dest_response.status_code == 200:
                destinations = dest_response.json().get("data", [])
                for dest in destinations:
                    if target_domain.lower() in dest.get("destination", "").lower():
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

    except requests.exceptions.RequestException as e:
        print(f"[-] Destination Lists API request failed: {e}")

def main():
    if len(sys.argv) < 2:
        target_domain = input("Enter the domain to search (e.g., google.com): ").strip()
        if not target_domain:
            print("[-] No domain provided. Exiting.")
            sys.exit(1)
    else:
        target_domain = sys.argv[1]
        
    # Step 1: Authentication using credentials from configuration block
    token = get_access_token(UMBRELLA_CLIENT_ID, UMBRELLA_CLIENT_SECRET)
    if not token:
        return
        
    # Step 2: Check Traffic Logs (Using your exact Postman query framework)
    query_dns_activity(token, target_domain)
    
    # Step 3: Check Policy Configurations
    scan_destination_lists(token, target_domain)

if __name__ == "__main__":
    main()
