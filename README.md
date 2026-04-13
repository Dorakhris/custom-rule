**1. File Hashes (SHA-256)**
*   `ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa` *(WannaCry Payload)*
*   `b9c5d4339809e0ad9a00d4d3dd26fdf44a32819a54abf846bb9b560d81391c25` *(WannaCry Decryptor)*
*   `1f3c7379dd29298aa24b3aa3a3113ed3051f4515bc3c016893e285d311a74202` *(AsyncRAT Payload)*
*   `b773ca84f8a93ac8477e377178499e5f4bf65cf3fdf228c3c4a594fc19edd647` *(Failed Dropper)*

**2. Network Indicators (AsyncRAT)**
*   **Domain:** `donzola.duckdns.org`
*   **IP Address:** `192.169.69.26`
*   **Port:** `2000`

**3. Malicious Behaviors & Commands**
*   **WannaCry Hiding:** `attrib.exe +h .`
*   **WannaCry ACL Mod:** `icacls . /grant Everyone:F /T /C /Q`
*   **Dropper Task:** `MUI unattend action{A4F3H6J4-Q1V4N7A5E3J7J8-A1C4N6D4K7D4}`

**4. Registry & File Artifacts**
*   **Registry Key:** `HKCU\SOFTWARE\WanaCrypt0r`
*   **Files:** `@Please_Read_Me@.txt`, `.wnry` extensions

---

#### **Step 1: Navigate to the Analytics Dashboard**
1. Log in to the [Azure Portal](https://portal.azure.com/).
2. Search for and select **Microsoft Sentinel**. Select your workspace.
3. On the left-hand menu, under the **Configuration** section, click on **Analytics**.
4. At the top, click **+ Create** and select **Scheduled query rule**.

#### **Step 2: The "General" Tab**

Yes, you absolutely can! In a real-world Security Operations Center (SOC), we often create what is called an **"Omnibus Rule"** or a **"Campaign Rule."** 

Instead of having 5 different alerts firing for the same incident, we write one master query that looks at *every* table (Files, Network, Processes, Registry) and combines any matches into a single, high-priority alert.

To do this, we use the KQL `union` command. We will search each table separately, format the columns so they match, and then merge them all together. 

Here is your **All-In-One Master Detection Rule** for your project report. 

### Microsoft Sentinel Alert Configuration:
*   **Alert Name:** `SOC Alert:  Comprehensive Malware Campaign Detection`
*   **Description:** `A consolidated detection rule that hunts for all known Indicators of Compromise (Hashes, C2 Traffic, LOLBin Commands, Registry Keys, Mutexes, and File Artifacts) associated with recent malware outbreaks.`
*   **Severity:** **Critical**
*   **MITRE ATT&CK Tactics:** `Initial Access`, `Execution`, `Persistence`, `Command and Control`, `Impact`

### The Master KQL Query:

```kusto
let hashHits = DeviceFileEvents
| where SHA256 in~ (
    "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa", // WannaCry
    "b9c5d4339809e0ad9a00d4d3dd26fdf44a32819a54abf846bb9b560d81391c25", // WanaDecryptor
    "1f3c7379dd29298aa24b3aa3a3113ed3051f4515bc3c016893e285d311a74202", // AsyncRAT
    "b773ca84f8a93ac8477e377178499e5f4bf65cf3fdf228c3c4a594fc19edd647"  // Dropper
)
| project TimeGenerated, DeviceName, AccountName, DetectionType = "Malicious Hash", Evidence = SHA256, MalwareFamily = "Multiple";

let networkHits = DeviceNetworkEvents
| where RemoteUrl =~ "donzola.duckdns.org" or RemoteIP == "192.169.69.26"
| project TimeGenerated, DeviceName, AccountName, DetectionType = "C2 Network Traffic", Evidence = coalesce(RemoteUrl, RemoteIP), MalwareFamily = "AsyncRAT";

let processHits = DeviceProcessEvents
| where ProcessCommandLine has_any (
    "attrib.exe +h", 
    "icacls . /grant Everyone:F /T /C /Q", 
    "MUI unattend action{A4F3H6J4"
)
| project TimeGenerated, DeviceName, AccountName, DetectionType = "Malicious Command", Evidence = ProcessCommandLine, MalwareFamily = "WannaCry / Dropper";

let fileArtifactHits = DeviceFileEvents
| where FileName =~ "@Please_Read_Me@.txt" 
     or FileName =~ "@WanaDecryptor@.exe" 
     or FileName endswith ".wnry"
| project TimeGenerated, DeviceName, AccountName, DetectionType = "Ransomware Artifact", Evidence = FileName, MalwareFamily = "WannaCry";

let registryHits = DeviceRegistryEvents
| where RegistryKey contains "WanaCrypt0r"
| project TimeGenerated, DeviceName, AccountName, DetectionType = "Registry Persistence", Evidence = RegistryKey, MalwareFamily = "WannaCry";

let mutexHits = DeviceEvents
| where ActionType == "MutexCreated" and AdditionalFields contains "AsyncMutex_iuykt5yr5ur58n8tnur8herjncr8tk"
| project TimeGenerated, DeviceName, AccountName, DetectionType = "Malware Mutex", Evidence = "AsyncMutex_iuykt5yr5ur58n8tnur8herjncr8tk", MalwareFamily = "AsyncRAT";

union isfuzzy=true hashHits, networkHits, processHits, fileArtifactHits, registryHits, mutexHits
| sort by TimeGenerated desc
```

**Scroll down to configure the Query Scheduling:**
*   **Run query every:** `10 Minutes`
*   **Lookup data from the last:** `10 Minutes`


#### **Step 4: Incident Settings & Automated Response**
1.  Click **Next: Incident settings >**.
2.  Ensure **Create incidents from alerts triggered by this analytics rule** is set to **Enabled**.
3.  Under **Alert grouping**, you can leave it as default 
4.  Click **Next: Automated response >**. 
5.  Click **Next: Review and create >**, then click **Save**.



