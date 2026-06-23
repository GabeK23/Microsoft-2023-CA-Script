$secureBootEnabled = $false
try { $secureBootEnabled = Confirm-SecureBootUEFI -ErrorAction Stop } catch { }

if (-not $secureBootEnabled) {
$logpath = "C:\Support\UEFI_Logs"
$logfile = Join-Path $logpath "UEFI_Log.json"

# Load existing log if present (preserves the counter across runs)
$log = $null
if (Test-Path $logfile) {
    try { $log = Get-Content $logfile -Raw | ConvertFrom-Json } catch { }
}

# Initialize or increment
if ($null -eq $log) {
    $log = @{
        Hostname          = $env:COMPUTERNAME
        SecureBootEnabled = $false
        FailCount         = 1
        FirstSeen         = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        LastSeen          = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    }
} else {
    $log = @{
        Hostname          = $env:COMPUTERNAME
        SecureBootEnabled = $false
        FailCount         = ([int]$log.FailCount + 1)
        FirstSeen         = $log.FirstSeen
        LastSeen          = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    }
}

if (-not (Test-Path $logpath)) { New-Item -ItemType Directory -Path $logpath | Out-Null }
$log | ConvertTo-Json | Out-File -FilePath $logfile -Force

Write-Host "Secure Boot is not enabled. Cannot remediate from Windows."
Write-Host "Requires manual action at BIOS/vSphere layer."
Write-Host "This machine has been flagged $($log.FailCount) time(s) since $($log.FirstSeen)."
exit 1
}

# Everything below only runs if Secure Boot IS enabled

$regkey = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name "AvailableUpdates"
$uefica2023Status = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" -ErrorAction SilentlyContinue).UEFICA2023Status

# 16-25. Event Log queries
# Event IDs:
#   1801 - Update initiated, reboot required
#   1808 - Update completed successfully
#   1795 - Firmware returned error (capture error code)
#   1796 - Error logged with error code (capture code)
#   1800 - Reboot needed (NOT an error - update will proceed after reboot)
#   1802 - Known firmware issue blocked update (capture KI_<number> from SkipReason)
#   1803 - Matching KEK update not found (OEM needs to supply PK signed KEK)
# PS Version: 3.0+ | Admin: May be required for System log | System Requirements: None
try {
    # Query all relevant Secure Boot event IDs
    $allEventIds = @(1795, 1796, 1800, 1801, 1802, 1803, 1808)
    $events = @(Get-WinEvent -FilterHashtable @{LogName='System'; ID=$allEventIds} -MaxEvents 50 -ErrorAction Stop)

    if ($events.Count -eq 0) {
        Write-Warning "No Secure Boot events found in System log"
        $latestEventId = $null
        $bucketId = $null
        $confidence = $null
        $skipReasonKnownIssue = $null
        $event1801Count = 0
        $event1808Count = 0
        $event1795Count = 0
        $event1795ErrorCode = $null
        $event1796Count = 0
        $event1796ErrorCode = $null
        $event1800Count = 0
        $rebootPending = $false
        $event1802Count = 0
        $knownIssueId = $null
        $event1803Count = 0
        $missingKEK = $false
        Write-Host "Latest Event ID: Not Available"
        Write-Host "Bucket ID: Not Available"
        Write-Host "Confidence: Not Available"
        Write-Host "Event 1801 Count: 0"
        Write-Host "Event 1808 Count: 0"
    } else {
        # 16. LatestEventId
        $latestEvent = $events | Sort-Object TimeCreated -Descending | Select-Object -First 1
        if ($null -eq $latestEvent) {
            Write-Warning "Could not determine latest event"
            $latestEventId = $null
            Write-Host "Latest Event ID: Not Available"
        } else {
            $latestEventId = $latestEvent.Id
            Write-Host "Latest Event ID: $latestEventId"
        }

        # 17. BucketID - Extracted from Event 1801/1808
        if ($null -ne $latestEvent -and $null -ne $latestEvent.Message) {
            if ($latestEvent.Message -match 'BucketId:\s*(.+)') {
                $bucketId = $matches[1].Trim()
                Write-Host "Bucket ID: $bucketId"
            } else {
                Write-Warning "BucketId not found in event message"
                $bucketId = $null
                Write-Host "Bucket ID: Not Found in Event"
            }
        } else {
            Write-Warning "Latest event or message is null, cannot extract BucketId"
            $bucketId = $null
            Write-Host "Bucket ID: Not Available"
        }

        # 18. Confidence - Extracted from Event 1801/1808
        if ($null -ne $latestEvent -and $null -ne $latestEvent.Message) {
            if ($latestEvent.Message -match 'BucketConfidenceLevel:\s*(.+)') {
                $confidence = $matches[1].Trim()
                Write-Host "Confidence: $confidence"
            } else {
                Write-Warning "Confidence level not found in event message"
                $confidence = $null
                Write-Host "Confidence: Not Found in Event"
            }
        } else {
            Write-Warning "Latest event or message is null, cannot extract Confidence"
            $confidence = $null
            Write-Host "Confidence: Not Available"
        }

        # 18b. SkipReason - Extract KI_<number> from SkipReason in the same event as BucketId
        # This captures Known Issue IDs that appear alongside BucketId/Confidence (not just Event 1802)
        $skipReasonKnownIssue = $null
        if ($null -ne $latestEvent -and $null -ne $latestEvent.Message) {
            if ($latestEvent.Message -match 'SkipReason:\s*(KI_\d+)') {
                $skipReasonKnownIssue = $matches[1]
                Write-Host "SkipReason Known Issue: $skipReasonKnownIssue" -ForegroundColor Yellow
            }
        }

        # 19. Event1801Count
        $event1801Array = @($events | Where-Object {$_.Id -eq 1801})
        $event1801Count = $event1801Array.Count
        Write-Host "Event 1801 Count: $event1801Count"

        # 20. Event1808Count
        $event1808Array = @($events | Where-Object {$_.Id -eq 1808})
        $event1808Count = $event1808Array.Count
        Write-Host "Event 1808 Count: $event1808Count"
        
        # Initialize error event variables
        $event1795Count = 0
        $event1795ErrorCode = $null
        $event1796Count = 0
        $event1796ErrorCode = $null
        $event1800Count = 0
        $rebootPending = $false
        $event1802Count = 0
        $knownIssueId = $null
        $event1803Count = 0
        $missingKEK = $false
        
        # Only check for error events if update is NOT complete
        # Skip error analysis if: 1808 is latest event OR UEFICA2023Status is "Updated"
        $updateComplete = ($latestEventId -eq 1808) -or ($uefica2023Status -eq "Updated")
        
        if (-not $updateComplete) {
            Write-Host "Update not complete - checking for error events..." -ForegroundColor Yellow
            
            # 21. Event1795 - Firmware Error (capture error code)
            $event1795Array = @($events | Where-Object {$_.Id -eq 1795})
            $event1795Count = $event1795Array.Count
            if ($event1795Count -gt 0) {
                $latestEvent1795 = $event1795Array | Sort-Object TimeCreated -Descending | Select-Object -First 1
                if ($latestEvent1795.Message -match '(?:error|code|status)[:\s]*(?:0x)?([0-9A-Fa-f]{8}|[0-9A-Fa-f]+)') {
                    $event1795ErrorCode = $matches[1]
                }
                Write-Host "Event 1795 (Firmware Error) Count: $event1795Count" $(if ($event1795ErrorCode) { "Code: $event1795ErrorCode" })
            }
            
            # 22. Event1796 - Error Code Logged (capture error code)
            $event1796Array = @($events | Where-Object {$_.Id -eq 1796})
            $event1796Count = $event1796Array.Count
            if ($event1796Count -gt 0) {
                $latestEvent1796 = $event1796Array | Sort-Object TimeCreated -Descending | Select-Object -First 1
                if ($latestEvent1796.Message -match '(?:error|code|status)[:\s]*(?:0x)?([0-9A-Fa-f]{8}|[0-9A-Fa-f]+)') {
                    $event1796ErrorCode = $matches[1]
                }
                Write-Host "Event 1796 (Error Logged) Count: $event1796Count" $(if ($event1796ErrorCode) { "Code: $event1796ErrorCode" })
            }
            
            # 23. Event1800 - Reboot Needed (NOT an error - update will proceed after reboot)
            $event1800Array = @($events | Where-Object {$_.Id -eq 1800})
            $event1800Count = $event1800Array.Count
            $rebootPending = $event1800Count -gt 0
            if ($rebootPending) {
                Write-Host "Event 1800 (Reboot Pending): Update will proceed after reboot" -ForegroundColor Cyan
            }
            
            # 24. Event1802 - Known Firmware Issue (capture KI_<number> from SkipReason)
            $event1802Array = @($events | Where-Object {$_.Id -eq 1802})
            $event1802Count = $event1802Array.Count
            if ($event1802Count -gt 0) {
                $latestEvent1802 = $event1802Array | Sort-Object TimeCreated -Descending | Select-Object -First 1
                if ($latestEvent1802.Message -match 'SkipReason:\s*(KI_\d+)') {
                    $knownIssueId = $matches[1]
                }
                Write-Host "Event 1802 (Known Firmware Issue) Count: $event1802Count" $(if ($knownIssueId) { "KI: $knownIssueId" })
            }
            
            # 25. Event1803 - Missing KEK Update (OEM needs to supply PK signed KEK)
            $event1803Array = @($events | Where-Object {$_.Id -eq 1803})
            $event1803Count = $event1803Array.Count
            $missingKEK = $event1803Count -gt 0
            if ($missingKEK) {
                Write-Host "Event 1803 (Missing KEK): OEM needs to supply PK signed KEK" -ForegroundColor Yellow
            }
        } else {
            Write-Host "Update complete (Event 1808 or Status=Updated) - skipping error analysis" -ForegroundColor Green
        }
    }
} catch {
    Write-Warning "Error retrieving event logs. May require administrator privileges: $_"
    $latestEventId = $null
    $bucketId = $null
    $confidence = $null
    $skipReasonKnownIssue = $null
    $event1801Count = 0
    $event1808Count = 0
    $event1795Count = 0
    $event1795ErrorCode = $null
    $event1796Count = 0
    $event1796ErrorCode = $null
    $event1800Count = 0
    $rebootPending = $false
    $event1802Count = 0
    $knownIssueId = $null
    $event1803Count = 0
    $missingKEK = $false
    Write-Host "Latest Event ID: Error"
    Write-Host "Bucket ID: Error"
    Write-Host "Confidence: Error"
    Write-Host "Event 1801 Count: 0"
    Write-Host "Event 1808 Count: 0"
}

if ($uefica2023Status -eq "Not Started") {
    Write-Error "UEFI CA 2023 Status is NOT compliant."
   #exit 1
} else {
    Write-Host "UEFI Status: $uefica2023Status"
} 

#Checks if the AvailableUpdates Registry Key is not equal to 0
   if($null -ne $regkey.AvailableUpdates -and $regkey.AvailableUpdates -ne 0){
      Write-Host "System meets compliance"
   } else {
     Write-Host "Setting AvailableUpdates = 0x5944"
     Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name "AvailableUpdates" -Value 0x5944 -Type DWord

     Write-Host "Starting Secure-Boot-Update scheduled task"
     Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
   }