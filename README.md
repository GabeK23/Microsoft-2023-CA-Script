# UEFI Secure Boot Compliance

## Overview

This project contains two PowerShell scripts used with Microsoft Intune Proactive Remediations to verify and remediate devices for the Microsoft UEFI CA 2023 Secure Boot update.

- **Detection (Evaluation)** - Checks whether the device is compliant with Microsoft's Secure Boot certificate requirements.
- **Remediation** - Configures the required registry value and starts the Windows Secure Boot update process if remediation is needed.

---

# Detection (Evaluation)

The detection script performs the following:

- Verifies Secure Boot is enabled.
- Reads the Secure Boot DB and KEK variables.
- Checks for the required UEFI CA 2023 certificates.
- Determines compliance based on Microsoft's guidance.
- Creates a JSON log of the results.
- Returns an exit code for Intune.

### Compliance Logic

If **UEFI CA 2011** is present, the following certificates are required:

- Windows UEFI CA 2023
- KEK CA 2023
- Microsoft UEFI CA 2023
- Option ROM UEFI CA 2023

If **UEFI CA 2011** is **not** present, only these certificates are required:

- Windows UEFI CA 2023
- KEK CA 2023

### Detection Exit Codes

| Exit Code | Description |
|-----------|-------------|
| 0 | Device is compliant |
| 1 | Device is not compliant or Secure Boot is disabled |

---

# Remediation

The remediation script performs the following:

- Verifies Secure Boot is enabled.
- Checks the current UEFI CA 2023 update status.
- Reviews Secure Boot related Windows Event Logs.
- Verifies the `AvailableUpdates` registry value.
- Sets the registry value if it is missing.
- Starts the Windows **Secure-Boot-Update** scheduled task.

### Registry Changes

If remediation is required, the following registry value is configured:

```
HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot
```

| Value | Data |
|-------|------|
| AvailableUpdates | 0x5944 |

### Scheduled Task

After setting the registry value, the script starts:

```
\Microsoft\Windows\PI\Secure-Boot-Update
```

This allows Windows to begin installing the Secure Boot certificate updates.

### Event IDs Monitored

| Event ID | Description |
|----------|-------------|
| 1795 | Firmware returned an error |
| 1796 | Error code logged |
| 1800 | Reboot required |
| 1801 | Update initiated |
| 1802 | Known firmware issue |
| 1803 | Matching KEK update not found |
| 1808 | Update completed successfully |

### Remediation Exit Codes

| Exit Code | Description |
|-----------|-------------|
| 0 | Remediation completed successfully |
| 1 | Secure Boot is disabled or remediation could not continue |

---

# Logging

Both scripts create logs in:

```
C:\Support\UEFI_Logs\
```

The detection script records compliance information, including:

- Computer Name
- Collection Time
- OEM Manufacturer
- Firmware Version
- Certificate Status
- Compliance Status

If Secure Boot is disabled, the remediation script records:

- Computer Name
- First Seen
- Last Seen
- Failure Count

---

# Requirements

- Windows 10/11
- UEFI firmware
- Secure Boot supported
- Administrator privileges
- Microsoft Intune Proactive Remediations (recommended)

---

# Notes

- The detection script is **read-only** and does not modify the system.
- The remediation script **modifies the `AvailableUpdates` registry value** and starts Microsoft's built-in **Secure-Boot-Update** scheduled task.
- Neither script directly updates UEFI firmware or Secure Boot certificates. Those updates are performed by Windows after remediation and may require one or more reboots to complete.

- The detection script is **read-only** and does not modify the system.
- The remediation script **modifies the `AvailableUpdates` registry value** and starts Microsoft's built-in **Secure-Boot-Update** scheduled task.
- Neither script directly updates UEFI firmware or Secure Boot certificates. Those updates are performed by Windows after remediation and may require one or more reboots to complete.
