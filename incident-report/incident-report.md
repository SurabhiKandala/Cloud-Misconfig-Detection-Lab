# 🚨 Incident Report — Azure Blob Public Access Abuse

---

## 📌 Summary

A misconfigured Azure Storage account allowed public (anonymous) access to blob data.  
An attacker exploited this misconfiguration to access and enumerate files, generating high-volume activity detected by Microsoft Sentinel.

---

## 🕒 Timeline

- **T1:** Storage account created with public access enabled  
- **T2:** Public container (`public-demo`) created  
- **T3:** Files uploaded (sensitive-looking data)  
- **T4:** External access simulated (listing + downloading blobs)  
- **T5:** Logs generated in `StorageBlobLogs`  
- **T6:** Detection rule triggered in Microsoft Sentinel  
- **T7:** Incident created and investigated  

---

## ⚠️ Misconfiguration

- Blob anonymous access enabled  
- Public container exposed to internet  
- No access restrictions applied  

---

## 💥 Attack Simulation

- Accessed blob container from browser (anonymous access)  
- Listed blobs (`ListBlobs`)  
- Downloaded files multiple times  
- Generated high-volume requests from same IP  

---

## 📊 Detection Logic

KQL Query used:

```kql
StorageBlobLogs
| extend SourceIP = tostring(split(CallerIpAddress, ":")[0])
| summarize 
    OperationCount = count(),
    FilesAccessed = dcount(Uri),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
by SourceIP
| where OperationCount > 10
| order by OperationCount desc

```

## 🚨 Alert Details

- **Rule Name:** Blob High Volume Access  
- **Severity:** Medium  
- **Trigger:** High number of operations from single IP  
- **Data Source:** StorageBlobLogs  

---

## 🕵️ Investigation Findings

- Suspicious IP identified performing repeated operations  
- High volume of blob access within short timeframe  
- Activity pattern indicates enumeration + data access  
- Authentication type: Anonymous / SAS  

---

## 🧠 MITRE ATT&CK Mapping

- **Collection (TA0009)** — Data from Cloud Storage  
- **Exfiltration (TA0010)** — Data download activity  

---

## 🏆 Outcome

Successfully demonstrated:

**Misconfiguration → Exploitation → Detection → Alert → Investigation**

---

## 🛡️ Recommendations

- Disable public (anonymous) blob access  
- Use private containers with IAM controls  
- Enable logging and monitoring by default  
- Implement alerting for abnormal access patterns  
- Restrict access using network rules / private endpoints  

---

## ⚙️ Tools & Technologies

- Microsoft Azure  
- Azure Storage Account  
- Microsoft Sentinel (SIEM)  
- Azure Monitor Logs  
- KQL (Kusto Query Language)  
