# Splunk for Cybersecurity Professionals

Important Considerations Before Implementation:
 * Log Sources: Ensure Splunk is receiving the necessary logs.
   * Windows: Windows Event Logs (System, Application, Security), Sysmon (highly recommended), dedicated File Integrity Monitoring (FIM) tool logs (e.g., Splunk’s native FIM via Universal Forwarder, Tripwire, Wazuh), HIDS logs (e.g., Wazuh agent, OSSEC, EDR HIDS features), Performance Logs (e.g., from Perfmon, Splunk App for Infrastructure).
   * Linux: Syslog (/var/log/syslog, /var/log/messages, /var/log/auth.log, /var/log/kern.log), Auditd (critical for detailed FIM and system call monitoring), dedicated FIM tool logs, HIDS logs, Performance Logs (e.g., from sar, collectd, Splunk App for Infrastructure).
 * Splunk Apps & Add-ons (TAs):
   * For Sysmon: Splunk Add-on for Microsoft Sysmon.
   * For FIM/HIDS: Specific TAs for your tools (e.g., TA for Wazuh).
   * For Performance: Splunk App for Infrastructure or TAs for specific performance collection methods.
 * Field Extractions: Queries rely on common field names. Adjust these based on your data sources and TAs (e.g., EventCode, System_Time, FileName, ProcessName, RuleDescription, severity, cpu_usage, mem_usage, disk_free_percent).
 * Indexes: Replace placeholders like Your_Windows_Index, Your_Sysmon_Index, Your_FIM_Index, Your_HIDS_index, Your_Perf_Index, Your_Linux_Index, Your_Auditd_Index with your actual Splunk index names.
 * Thresholds & Tuning: Many queries involve thresholds (e.g., “cpu_usage > 90”). These are starting points and should be tuned to your environment’s baseline to reduce false positives. Statistical methods (like stdev or anomalydetection command) are preferable for anomaly detection.

### Systems Security Posture Dashboard

#### Domains: Critical Alerts, High/Critical Unpatched Vulnerabilities, Active Endpoint Detections, Alert/Detection Statistics

* Goal: Provide a high-level, real-time snapshot of the overall security health across all monitored systems. Enable quick identification of major emerging issues or areas needing immediate attention.

* Target Audience: SOC Analysts (Tier ½), SOC Managers, CSSP Leadership.

* Key Data Sources: Aggregated data from all relevant sources (Endpoint Security, Auth Logs, Vulnerability Scans, OS Logs).

### Authentication and Access Management Dashboard

#### Domains: Suspicious Login Activity, Unauthorized Access Attempts, Privilege Escalation

* Goal: Detect and investigate suspicious login activity, unauthorized access attempts, and privilege escalation across all monitored systems.

* Target Audience: SOC Analysts (Tier ½), Incident Responders.

* Key Data Sources: Authentication Logs (Windows Security Events 4624, 4625, 4768, 4769, 4771, 4776; Linux /var/log/secure or auth.log; SSH logs), Active Directory logs, Privileged Access Management (PAM) logs.

### Endpoint Protection and Vulnerability Management Dashboard

#### Domains: Endpoint Security Controls Status, Active Threats, Missing Patches, Endpoint Detection and Response (EDR) Specific Alerts, Virus and Malware, Vulnerability Scanner Insights, Policy Infraction

* Goal: Monitor the effectiveness of endpoint security controls (AV/EDR), track vulnerability status, and identify systems at high risk due to missing patches or active threats.

* Target Audience: SOC Analysts, Vulnerability Management Team, System Administrators (via reports).

* Key Data Sources: Endpoint Detection & Response (EDR) logs, Antivirus (AV) logs, Vulnerability Scanner results (e.g., Nessus, Qualys), Patch Management system data (if available), OS logs indicating patch status.

### System Integrity and Anomaly Detection Dashboard

#### Domains: OS, File Integrity Monitoring, Basic Performance Metrics (Anomalies)

* Goal: Detect deviations from baseline system behavior, unauthorized changes, critical system errors, and other potentially malicious activities that might bypass standard signatures.

* Target Audience: SOC Analysts (Tier 2/3), Incident Responders, System Forensics.

* Key Data Sources: OS Logs (Critical errors, service changes, process creation – e.g., Sysmon, Windows Event Logs, auditd), File Integrity Monitoring (FIM) logs, Host-based Intrusion Detection System (HIDS) alerts, basic performance metrics (CPU/Memory spikes – can indicate crypto-mining or DoS activity).
