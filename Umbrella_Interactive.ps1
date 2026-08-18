<#
.SYNOPSIS
UmbrellaReporting.ps1
1. Queries DNS activity logs using your exact working Postman URL configuration.
2. Scans all Policy Destination Lists to see if the domain is explicitly configured.
3. I was asked to rewrite this in Powershell. I inverted the Umbrella because I do not like Powershell.
#>

# ==================== CONFIGURATION BLOCK ====================
# Paste your Cisco Umbrella API Client ID and Secret here for testing
$UMBRELLA_CLIENT_ID = ""
$UMBRELLA_CLIENT_SECRET = ""
# =============================================================

$ASCII_ART = @'
            r       
        ' ' | ` `   
         \_\_/_/    
          `-v-'     

 _   _ __  __ ____  ____  _____ _     _        _    
| | | |  \/  | __ )|  _ \| ____| |   | |      / \   
| | | | |\/| |  _ \| |_) |  _| | |   | |     / _ \  
| |_| | |  | | |_) |  _ <| |___| |___| |___ / ___ \ 
 \___/|_|  |_|____/|_| \_\_____|_____|_____/_/   \_\
       Reporting & Policy Scanner
'@

function Get-AccessToken {
    <# Exchanges Client Credentials for a temporary OAuth2 Bearer token. #>
    $TokenUrl = "https://api.umbrella.com/auth/v2/token"
    
    if ([string]::IsNullOrWhiteSpace($UMBRELLA_CLIENT_ID) -or [string]::IsNullOrWhiteSpace($UMBRELLA_CLIENT_SECRET) -or $UMBRELLA_CLIENT_ID -match "YOUR_UMBRELLA_") {
        Write-Host "[!] Error: Please update the CONFIGURATION BLOCK with your real API keys." -ForegroundColor Red
        exit 1
    }
        
    try {
        # Basic Auth encoding required for token request
        $AuthBytes = [System.Text.Encoding]::UTF8.GetBytes("${UMBRELLA_CLIENT_ID}:${UMBRELLA_CLIENT_SECRET}")
        $EncodedAuth = [Convert]::ToBase64String($AuthBytes)

        $Headers = @{
            "Authorization" = "Basic $EncodedAuth"
            "Content-Type"  = "application/x-www-form-urlencoded"
        }
        $Body = "grant_type=client_credentials"

        $Response = Invoke-RestMethod -Uri $TokenUrl -Method Post -Headers $Headers -Body $Body -ErrorAction Stop
        return $Response.access_token
    } catch {
        Write-Host "[-] Authentication failed: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

function Query-DnsActivity {
    <# Queries DNS activity logs using your exact working Postman URL string. #>
    param (
        [string]$Token,
        [string]$TargetDomain
    )

    $Url = "https://api.umbrella.com/reports/v2/activity/dns?domains=$TargetDomain&from=-30days&to=now&limit=20"
    
    $Headers = @{
        "Authorization" = "Bearer $Token"
        "Accept"        = "application/json"
    }
    
    Write-Host "`n[*] Executing Reporting Query for: '$TargetDomain'..." -ForegroundColor Cyan
    
    try {
        $Response = Invoke-RestMethod -Uri $Url -Method Get -Headers $Headers -ErrorAction Stop
        
        # THE FIX: Umbrella API v2 stores the records in the "data" array
        $Data = $Response.data
        
        if ($Data -and $Data.Count -gt 0) {
            Write-Host "[+] Found $($Data.Count) recent query log(s):" -ForegroundColor Green
            foreach ($Record in $Data) {
                # 1. Robust action/verdict extraction
                $Action = "Unknown"
                if ($null -ne $Record.verdict) {
                    $Action = $Record.verdict.ToString()
                } elseif ($null -ne $Record.allowed) {
                    $Action = if ($Record.allowed) { "Allowed" } else { "Blocked" }
                } elseif ($null -ne $Record.action) {
                    $Action = $Record.action.ToString()
                }

                # Capitalize first letter of Action
                if ($Action.Length -gt 1) {
                    $Action = $Action.Substring(0,1).ToUpper() + $Action.Substring(1).ToLower()
                }
                
                # 2. Robust identity extraction
                $Identity = "Unknown Identity"
                if ($null -ne $Record.identityName) {
                    $Identity = $Record.identityName
                } elseif ($null -ne $Record.identities -and $Record.identities.Count -gt 0) {
                    $Identity = $Record.identities[0].label
                }
                if ([string]::IsNullOrWhiteSpace($Identity)) { $Identity = "Unknown" }
                
                # 3. Clean up the timestamp
                $RawTime = if ($null -ne $Record.timestamp) { $Record.timestamp.ToString() } else { "N/A" }
                $CleanTime = if ($RawTime -ne "N/A") { 
                    $Formatted = $RawTime.Replace("T", " ")
                    if ($Formatted.Length -ge 19) { $Formatted.Substring(0, 19) } else { $Formatted }
                } else { 
                    $RawTime 
                }
                
                Write-Host ("    - Action: {0,-7} | Identity: {1} | Time: {2}" -f $Action, $Identity, $CleanTime)
            }
        } else {
            Write-Host "[-] No matching domain traffic found in reporting logs for the last 30 days." -ForegroundColor Yellow
        }
            
    } catch {
        Write-Host "[-] Reporting API request failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Scan-DestinationLists {
    <# Fetches all existing destination lists and checks if the domain is inside them. #>
    param (
        [string]$Token,
        [string]$TargetDomain
    )

    $Headers = @{
        "Authorization" = "Bearer $Token"
        "Accept"        = "application/json"
    }
    $ListsUrl = "https://api.umbrella.com/policies/v2/destinationlists"
    
    Write-Host "`n[*] Scanning Destination Lists for configurations matching: '$TargetDomain'..." -ForegroundColor Cyan
    
    try {
        $Response = Invoke-RestMethod -Uri $ListsUrl -Method Get -Headers $Headers -ErrorAction Stop
        $Lists = $Response.data
        $MatchedLists = @()

        foreach ($DList in $Lists) {
            $ListId = $DList.id
            $ListName = $DList.name
            $ListType = $DList.access 
            
            # Fetch destinations inside this specific list
            $DestUrl = "https://api.umbrella.com/policies/v2/destinationlists/$ListId/destinations"
            
            try {
                $DestResponse = Invoke-RestMethod -Uri $DestUrl -Method Get -Headers $Headers -ErrorAction Stop
                $Destinations = $DestResponse.data
                
                foreach ($Dest in $Destinations) {
                    # -match in PowerShell is case-insensitive by default
                    if ($null -ne $Dest.destination -and $Dest.destination -match [regex]::Escape($TargetDomain)) {
                        $MatchedLists += [PSCustomObject]@{
                            Name  = $ListName
                            Id    = $ListId
                            Type  = $ListType
                            Entry = $Dest.destination
                        }
                    }
                }
            } catch {
                # Skip lists we can't read
            }
        }
                        
        if ($MatchedLists.Count -gt 0) {
            Write-Host "[!] Domain configuration found in the following lists:" -ForegroundColor Yellow
            foreach ($Match in $MatchedLists) {
                Write-Host "    - List: '$($Match.Name)' (ID: $($Match.Id)) | Type: $($Match.Type) | Configured Entry: $($Match.Entry)"
            }
        } else {
            Write-Host "[-] Domain not found in any existing Block or Allow destination lists." -ForegroundColor DarkGray
        }

    } catch {
        Write-Host "[-] Destination Lists API request failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Main {
    # Authenticate once before dropping into the menu loop
    Write-Host "[*] Authenticating with Cisco Umbrella API..." -ForegroundColor Cyan
    $Token = Get-AccessToken
    if (-not $Token) {
        return
    }
        
    while ($true) {
        Clear-Host
        Write-Host $ASCII_ART -ForegroundColor Green
        Write-Host ("=" * 65)
        Write-Host "  1. Full Search (DNS Activity & Destination Lists)"
        Write-Host "  2. Query DNS Activity Only"
        Write-Host "  3. Scan Destination Lists Only"
        Write-Host "  4. Exit"
        Write-Host ("=" * 65)
        
        $Choice = (Read-Host "`n[?] Select an option (1-4)").Trim()
        
        if ($Choice -eq '4') {
            Write-Host "`n[+] Exiting. Have a rad day!`n" -ForegroundColor Green
            break
        }
            
        if ($Choice -in @('1', '2', '3')) {
            $TargetDomain = (Read-Host "`n[?] Enter the domain to search (e.g., google.com)").Trim()
            
            if ([string]::IsNullOrEmpty($TargetDomain)) {
                Write-Host "`n[-] No domain provided. Please try again." -ForegroundColor Red
            } else {
                if ($Choice -eq '1') {
                    Query-DnsActivity -Token $Token -TargetDomain $TargetDomain
                    Scan-DestinationLists -Token $Token -TargetDomain $TargetDomain
                } elseif ($Choice -eq '2') {
                    Query-DnsActivity -Token $Token -TargetDomain $TargetDomain
                } elseif ($Choice -eq '3') {
                    Scan-DestinationLists -Token $Token -TargetDomain $TargetDomain
                }
            }
        } else {
            Write-Host "`n[-] Invalid selection. Please choose 1, 2, 3, or 4." -ForegroundColor Red
        }
            
        # Pause before looping back to the menu
        Read-Host "`nPress Enter to return to the main menu..." | Out-Null
    }
}

# Execute the script
Main
