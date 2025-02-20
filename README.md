<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/parkerang03/Threat-Hunting-Scenario-Tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user “parkerang” downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called `tor-shopping-list` on the desktop at `2025-02-20T19:54:45.2764586Z`. These events began at: `2025-02-20T19:36:56.1607237Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "gelo-vm"
| where InitiatingProcessAccountName == "parkerang"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-02-20T19:36:56.1607237Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, Account = InitiatingProcessAccountName
```
Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string “tor-browser-windows-x86_64-portable-14.0.6.exe”. Based on the logs returned, on the afternoon of February 20, 2025, at 2:38 PM, a computer named gelo-vm created a new process. The user parkerang downloaded and executed the Tor Browser installer (version 14.0.6, 64-bit, portable) from their Downloads folder on a Windows system. The installer was run with the /S flag, indicating a silent installation. The file had a unique SHA-256 hash for verification: 8396d2cd3859189ac38629ac7d71128f6596b5cc71e089ce490f86f14b4ffb94.

![image](https://github.com/user-attachments/assets/6c29635c-62b4-4519-b86f-204b7b10f6bc)

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any `ProcessCommandLine` that contained the string “tor-browser-windows-x86_64-portable-14.0.6.exe”. Based on the logs returned, on the afternoon of `February 20, 2025, at 2:38 PM`, a computer named gelo-vm created a new process. The user parkerang downloaded and executed `tor-browser-windows-x86_64-portable-14.0.6.exe` from their Downloads folder on a Windows system. The installer was run with the /S flag, indicating a silent installation. The file had a unique SHA-256 hash for verification: `8396d2cd3859189ac38629ac7d71128f6596b5cc71e089ce490f86f14b4ffb94`.


**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "gelo-vm"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.6.exe"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine, AccountName
```
![image](https://github.com/user-attachments/assets/8b3dfb13-58c2-439b-a1de-961f31d76e27)

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that the user “parkerang” actually opened the tor browser. There was evidence that they did open it at `2025-02-20T19:39:13.4991088Z`. There were several other instances of `firefox.exe` (Tor) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "gelo-vm"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe", "browser.exe", "torbrowser.exe", "torlauncher.exe", "tor-portable.exe")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine, AccountName
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/27a32cb1-ca3c-4f06-bf74-c19df180f787)

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Search the `DeviceNetworkEvents` table for any indication the tor browser was used to establish a connection using any of the known ports for tor. At `2:39 PM on February 20, 2025`, the computer `gelo-vm` successfully established an outbound connection. The user parkerang ran `tor.exe` from their Desktop's Tor Browser folder, initiating a connection to the remote IP `193.31.27.127` on port `9001` — a known Tor relay port. The connection was made to the URL `https://www.2e7xvichjf.com`, suggesting Tor network activity. There were a few other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "gelo-vm"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9050", "9051", "9150", "9151", "80", "443")
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessAccountName, InitiatingProcessFolderPath
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/75ac5e7e-c04c-4eb0-ac83-b0ff83366c51)

---

## Chronological Event Timeline 

# TOR Browser Threat Hunt Timeline

## 1. File Download - TOR Installer

- **Timestamp:** `2025-02-20T14:38:38Z`
- **Event:** The user "parkerang" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.6.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\parkerang\Downloads\tor-browser-windows-x86_64-portable-14.0.6.exe`

---

## 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-02-20T14:38:38Z`
- **Event:** The user "parkerang" executed the installer `tor-browser-windows-x86_64-portable-14.0.6.exe` in silent mode (`/S`), initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.6.exe /S`
- **File Path:** `C:\Users\parkerang\Downloads\tor-browser-windows-x86_64-portable-14.0.6.exe`

---

## 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-02-20T19:39:13.4991088Z`
- **Event:** The user "parkerang" opened the TOR Browser. This launch resulted in the creation of multiple TOR-related processes (e.g., `firefox.exe` and `tor.exe`), confirming that the browser started successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\parkerang\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

---

## 4. Network Connection - TOR Relay Connection

- **Timestamp:** `2025-02-20T14:39:28Z`
- **Event:** A network connection was established by `tor.exe` from the TOR Browser folder. The connection targeted remote IP `193.31.27.127` on port `9001`, a known TOR relay port.
- **Process:** `tor.exe`
- **File Path:** `C:\Users\parkerang\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

---

## 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-02-20T14:39:24Z` – Connection to remote IP `207.180.230.109` on port `443`.
  - `2025-02-20T14:39:27Z` – Connection to remote IP `46.22.165.111` on port `9001`.
- **Event:** Additional network connections associated with TOR Browser activity were detected, further indicating active TOR network use.
- **Action:** Multiple successful connections detected.

---

## 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-02-20T19:54:45.2764586Z`
- **Event:** The user "parkerang" created a file named `tor-shopping-list` on the desktop, which may indicate notes or a list related to TOR usage.
- **Action:** File creation detected.
- **File Path:** `C:\Users\parkerang\Desktop\tor-shopping-list`

---

## Summary

On February 20, 2025, user "parkerang" engaged in TOR Browser activity on the "gelo-vm" system. The timeline began with the download of the TOR installer from the Downloads folder and the subsequent silent execution to install the browser. Shortly after, the TOR Browser was launched, spawning multiple processes including instances of `firefox.exe` and `tor.exe`. Network activity consistent with TOR usage was observed, including a connection to a known TOR relay on port `9001`, along with additional connections over ports `443` and others. Finally, a file named `tor-shopping-list` was created on the desktop, suggesting further TOR-related actions or note-taking.

---

## Response Taken

TOR usage was confirmed on the endpoint `gelo-vm` by the user `parkerang`. The device was isolated, and the user's direct manager was notified.

---
