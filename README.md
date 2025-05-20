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

### Authentication and Access Management Dashboard

#### Domains: Suspicious Login Activity, Unauthorized Access Attempts, Privilege Escalation

### Endpoint Protection and Vulnerability Management Dashboard

#### Domains: Endpoint Security Controls Status, Active Threats, Missing Patches, Endpoint Detection and Response (EDR) Specific Alerts, Virus and Malware, Vulnerability Scanner Insights, Policy Infraction

### System Integrity and Anomaly Detection Dashboard

#### Domains: OS, File Integrity Monitoring, Basic Performance Metrics (Anomalies)
