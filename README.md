# Threat Event (Unauthorized Remote Access & Data Exfiltration)
**Unauthorized Use of AnyDesk/TeamViewer for Remote Access and Cloud Data Exfiltration**  

---

## Steps the "Bad Actor" Took to Create Logs and IoCs:
1. **Downloaded unauthorized remote access software**:  
   - **AnyDesk**: [Download](https://anydesk.com/en/downloads)  
   - **TeamViewer**: [Download](https://www.teamviewer.com/en/download/windows/)  

2. **Silently installed AnyDesk on the system:**  
   ```powershell
   Start-Process -FilePath "C:\Path\to\AnyDesk.exe" -ArgumentList "/silent" -Wait
   ```

3. **Created persistence mechanisms:**  
   - **Added AnyDesk to Windows Startup Registry:**  
     ```powershell
     reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "AnyDesk" /t REG_SZ /d "C:\Program Files (x86)\AnyDesk\AnyDesk.exe"
     ```
   - **Created a Scheduled Task for persistence:**  
     ```powershell
     schtasks /create /tn "AnyDesk AutoStart" /tr "C:\Program Files (x86)\AnyDesk\AnyDesk.exe" /sc onlogon /rl highest
     ```

4. **Accessed the machine remotely using AnyDesk:**  
   - Logged in remotely from a personal device.
   - Established a session by sharing the AnyDesk address.

5. **Exfiltrated data via cloud storage:**  
   - Opened **Google Drive, Dropbox, or OneDrive** in a browser.
   - Uploaded sensitive files (e.g., `HR_Report.xlsx`, `ClientData.zip`).
   - **Used PowerShell to automate file upload:**  
     ```powershell
     Start-Process "chrome.exe" "https://drive.google.com"
     ```

---

## Tables Used to Detect IoCs:

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**           | DeviceFileEvents |
| **Info**           | [Microsoft Docs - DeviceFileEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table) |
| **Purpose**        | Used for detecting unauthorized software installations and persistence mechanisms. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**           | DeviceProcessEvents |
| **Info**           | [Microsoft Docs - DeviceProcessEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table) |
| **Purpose**        | Used to detect remote access software execution and scheduled task creation. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**           | DeviceNetworkEvents |
| **Info**           | [Microsoft Docs - DeviceNetworkEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table) |
| **Purpose**        | Used to detect AnyDesk/TeamViewer network activity and suspicious file uploads to cloud storage. |

---

## Related Queries:

```kql
// Detect unauthorized remote access software installation
DeviceFileEvents
| where FileName has_any ("AnyDesk.exe", "TeamViewer.exe")
| where ActionType == "FileCreated"

// Detect AnyDesk persistence via Registry
DeviceRegistryEvents
| where RegistryKey contains "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
| where RegistryValueName in ("AnyDesk", "TeamViewer")

// Detect unauthorized remote access tool execution
DeviceProcessEvents
| where ProcessCommandLine has_any("AnyDesk.exe", "TeamViewer.exe")
| project Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

// Detect remote access session initiation
DeviceNetworkEvents
| where RemotePort in (3389, 5938, 7070) // RDP, AnyDesk, TeamViewer ports
| where InitiatingProcessFileName in ("AnyDesk.exe", "TeamViewer.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl

// Detect cloud data exfiltration (Google Drive, Dropbox)
DeviceNetworkEvents
| where RemoteUrl contains "drive.google.com" or RemoteUrl contains "dropbox.com"
| where InitiatingProcessFileName == "chrome.exe"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemoteUrl
| order by Timestamp desc
```

---

## Created By:
- **Author Name**: Eric
- **Author Contact**: [Your LinkedIn/GitHub/Email]  
- **Date**: February 2025  

## Validated By:
- **Reviewer Name**:  
- **Reviewer Contact**:  
- **Validation Date**:  

---

## Additional Notes:
- **This scenario highlights real-world insider threats using unauthorized remote access tools.**
- **Threat actors often use personal cloud storage for exfiltration to bypass DLP (Data Loss Prevention) policies.**

---

## Revision History:

| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | February 2025    | Eric |
