$secureBootEnabled = $false
try { $secureBootEnabled = Confirm-SecureBootUEFI -ErrorAction Stop } catch { }

$logpath = "C:\Support\UEFI_Logs"
$logfile = Join-Path $logpath "UEFI_Log.json"

if (-not $secureBootEnabled) {
    $log = @{
        Hostname       = $env:COMPUTERNAME
        collectionTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        SecureBoot     = "Disabled or not supported"
    }
    Write-Host "Secure Boot not enabled"
    if (-not (Test-Path -Path $logpath)) { New-Item -ItemType Directory -Path $logpath | Out-Null }
    $log | ConvertTo-Json | Out-File -FilePath $logfile -Force
    exit 1
}

Write-Host "Secure Boot Enabled: $secureBootEnabled"

$db1 = $false; $db2 = $false; $db3 = $false; $db4 = $false; $db5 = $false
try {
    $dbBytes  = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db  -ErrorAction Stop).Bytes)
    $kekBytes = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI KEK -ErrorAction Stop).Bytes)
    $db1 = bool
    $db2 = bool
    $db3 = bool
    $db4 = bool
    $db5 = bool
} catch {
    Write-Host "Failed to read UEFI variables: $($_.Exception.Message)"
    $log = @{
        Hostname       = $env:COMPUTERNAME
        collectionTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        SecureBoot     = "Enabled"
        Error          = "Failed to read UEFI variables: $($_.Exception.Message)"
    }
    if (-not (Test-Path -Path $logpath)) { New-Item -ItemType Directory -Path $logpath | Out-Null }
    $log | ConvertTo-Json | Out-File -FilePath $logfile -Force
    exit 1
}

$log = @{
    Hostname       = $env:COMPUTERNAME
    collectionTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    OEMMAn         = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -ErrorAction SilentlyContinue).OEMManufacturerName
    FirmwareVer    = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -ErrorAction SilentlyContinue).FirmwareVersion
    WindowsUEFI2023   = $db1
    KEK2023           = $db2
    MicrosoftUEFI2023 = $db3
    OptionROM2023     = $db4
    UEFCA2011         = $db5
}

# Conditional compliance per Microsoft playbook:
#   If UEFI CA 2011 is in the DB, all 4 certs are required.
#   If UEFI CA 2011 is NOT in the DB, only 2 are required.
Write-Host "DB:  Windows UEFI CA 2023            : $db1"
Write-Host "KEK: KEK 2K CA 2023                  : $db2"
Write-Host "DB:  Microsoft UEFI CA 2023 (3rd pty): $db3"
Write-Host "DB:  Option ROM UEFI CA 2023         : $db4"
Write-Host "DB:  UEFI CA 2011 (scope)            : $db5"

if ($db5) {
    Write-Host "UEFI CA 2011 is present -- all 4 certs required"
    $allCertsPresent = $db1 -and $db2 -and $db3 -and $db4
} else {
    Write-Host "UEFI CA 2011 is NOT present -- only 2 certs required"
    $allCertsPresent = $db1 -and $db2
}

$log.Compliant = $allCertsPresent
if (-not (Test-Path -Path $logpath)) { New-Item -ItemType Directory -Path $logpath | Out-Null }
$log | ConvertTo-Json | Out-File -FilePath $logfile -Force

if ($allCertsPresent) {
    Write-Host "All required certificates present -- compliant"
    exit 0
} else {
    Write-Host "One or more required certificates missing -- not compliant"
    exit 1
}