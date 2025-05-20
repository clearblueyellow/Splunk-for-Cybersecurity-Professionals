# Splunk for Cybersecurity Professionals

## Systems Security Posture Dashboard

### Critical Alerts

### High/Critical Unpatched Vulnerabilities

### Active Endpoint Detections

### Alert/Detection Statistics

## Authentication and Access Management Dashboard

### Suspicious Login Activity

#### Windows

##### Multiple Logins Followed by Success

Index=Your_Windows_Index EventCode=4625 OR EventCode=4624 action=failure OR action=success  
| stats count(eval(EventCode=4625)) as failed_logins, count(eval(EventCode=4624)) as successful_logins, earliest(_time) as first_attempt, latest(_time) as last_attempt by user, src_ip  
| where failed_logins > 5 AND successful_logins > 0 AND (last_attempt – first_attempt) < 1800  // Adjust failed_logins threshold and time window (1800 seconds = 30 minutes) as needed  
| sort -failed_logins  
| table user, src_ip, failed_logins, successful_logins, first_attempt, last_attempt

##### Logins from Unusual Geographic Locations

Index=Your_Windows_Index EventCode=4624 action=success  
| iplocation src_ip  
| search NOT (Country=”Your_Expected_Country_1” OR Country=”Your_Expected_Country_2”) // Add your expected countries  
| stats count by user, src_ip, City, Country  
| sort -count  
| table user, src_ip, City, Country, count  

##### Login Outside of Business Hours

Index=Your_Windows_Index EventCode=4624 action=success  
| eval hour = strftime(_time, “%H”)  
| where hour < 8 OR hour > 18 // Adjust hours as per your business schedule (e.g., < 8 AM or > 6 PM)  
| eval day_of_week = strftime(_time, “%w”) // 0=Sunday, 6=Saturday  
| where day_of_week != 0 AND day_of_week != 6 // Exclude weekends if needed  
| stats count by user, src_ip, _time, host  
| sort -_time  
| table user, src_ip, _time, host, count  

##### Concurrent Logins from Different IPs for the Same User

Index=Your_Windows_Index EventCode=4624 action=success  
| stats dc(src_ip) as distinct_ips, values(src_ip) as source_ips, earliest(_time) as first_login, latest(_time) as last_login by user  
| where distinct_ips > 1 AND (last_login – first_login) < 3600 // Adjust time window (3600 seconds = 1 hour) as needed  
| sort -distinct_ips  
| table user, distinct_ips, source_ips, first_login, last_login  

#### Linux

##### Multiple Failed SSH Logins Followed by Success

Index=Your_Linux_Index (sourcetype=linux_secure OR sourcetype=syslog) (Accepted OR Failed) password for *  
| rex “Accepted password for (?<user>\S+) from (?<src_ip>\S+)”  
| rex “Failed password for (invalid user )?(?<user>\S+) from (?<src_ip>\S+)”  
| eval status=if(match(_raw, “Accepted”), “success”, “failure”)  
| stats count(eval(status=”failure”)) as failed_logins, count(eval(status=”success”)) as successful_logins, earliest(_time) as first_attempt, latest(_time) as last_attempt by user, src_ip  
| where failed_logins > 5 AND successful_logins > 0 AND (last_attempt – first_attempt) < 1800 // Adjust threshold and time window  
| sort -failed_logins  
| table user, src_ip, failed_logins, successful_logins, first_attempt, last_attempt  

##### SSH Logins from Unusual Geographic Locations

Index=Your_Linux_Index (sourcetype=linux_secure OR sourcetype=syslog) “Accepted password for”  
| rex “Accepted password for (?<user>\S+) from (?<src_ip>\S+)”  
| iplocation src_ip  
| search NOT (Country=”Your_Expected_Country_1” OR Country=”Your_Expected_Country_2”) // Add your expected countries  
| stats count by user, src_ip, City, Country, host  
| sort -count  
| table user, src_ip, City, Country, host, count  

##### SSH Logins Outside of Business Hours

Index=Your_Linux_Index (sourcetype=linux_secure OR sourcetype=syslog) “Accepted password for”  
| rex “Accepted password for (?<user>\S+) from (?<src_ip>\S+)”  
| eval hour = strftime(_time, “%H”)  
| where hour < 8 OR hour > 18 // Adjust hours  
| eval day_of_week = strftime(_time, “%w”)  
| where day_of_week != 0 AND day_of_week != 6 // Exclude weekends  
| stats count by user, src_ip, _time, host  
| sort -_time  
| table user, src_ip, _time, host, count  

##### Concurrent SSH Logins from Different IPs for the Same User

Index=Your_Linux_Index (sourcetype=linux_secure OR sourcetype=syslog) “Accepted password for”  
| rex “Accepted password for (?<user>\S+) from (?<src_ip>\S+)”  
| stats dc(src_ip) as distinct_ips, values(src_ip) as source_ips, earliest(_time) as first_login, latest(_time) as last_login by user  
| where distinct_ips > 1 AND (last_login – first_login) < 3600 // Adjust time window  
| sort -distinct_ips  
| table user, distinct_ips, source_ips, first_login, last_login  

### Unauthorized Access Attempts

#### Windows

##### High Number of Failed Logins

Index=Your_Windows_Index EventCode=4625 action=failure  
| stats count by user, src_ip, dest_host  
| where count > 10 // Adjust threshold  
| sort -count  
| table user, src_ip, dest_host, count  

##### Failed Logins with Non-Existent Usernames

Index=Your_Windows_Index EventCode=4625 action=failure (Status=”0xc0000064” OR “Unknown user name or bad password”) // Status codes can vary; check your logs. “0xc0000064” usually means username does not exist.  
| stats count by user, src_ip, dest_host  
| sort -count  
| table user, src_ip, dest_host, count  

##### Access Attempts to Disabled Accounts

Index=Your_Windows_Index EventCode=4625 action=failure (Status=”0xc0000072” OR “Account disabled”) // Status codes can vary. “0xc0000072” often means account disabled.  
| stats count by user, src_ip, dest_host  
| sort -count  
| table user, src_ip, dest_host, count  

##### Kerberos Pre-Authentication Failures (AS-REP Roasting Potential)

Index=Your_Windows_Index EventCode=4768 “Failure Code: 0x18”  
| stats count by “Account Name”, “Client Address”  
| where count > 20 // Adjust threshold  
| rename “Account Name” as user, “Client Address” as src_ip  
| sort -count  
| table user, src_ip, count  

#### Linux

##### Failed SSH Logins with Non-Existent Usernames

Index=Your_Linux_Index (sourcetype=linux_secure OR sourcetype=syslog) “Failed password for invalid user”  
| rex “Failed password for invalid user (?<user>\S+) from (?<src_ip>\S+)”  
| stats count by user, src_ip, host  
| sort -count  
| table user, src_ip, host, count  

##### Attempts to Use su or sudo by Unauthorized Users

Index=Your_Linux_Index (sourcetype=linux_secure OR sourcetype=syslog) (“authentication failure” AND (sudo OR su)) OR (sudo AND “is not in the sudoers file”)  
| rex “(?<user>\S+)\s+:.*authentication failure”  
| rex “(?<user>\S+)\s+:.*is not in the sudoers file”  
| stats count by user, host, _raw  
| sort -count  
| table user, host, count, _raw  

### Privilege Escalation

#### Windows

##### User Added to Privileged Group

Index=Your_Windows_Index (EventCode=4728 OR EventCode=4732 OR EventCode=4756) (“Group Name”=”Domain Admins” OR “Group Name”=”Administrators” OR “Group Name”=”Enterprise Admins” OR “Group Name”=”Schema Admins”) // Add other privileged group SIDs or names  
| stats values(“Member Name”) as member_added, values(“TargetUserName”) as group_name, values(“SubjectUserName”) as added_by, _time, host  
| rename “Group Name” as GroupName // Ensure field name matches your extraction if different  
| table _time, member_added, GroupName, added_by, host

##### Special Privileges Assigned to New Logon

Index=Your_Windows_Index EventCode=4672  
| stats values(Privileges) as Privileges, count by SubjectUserName, SubjectDomainName, host  
| search NOT (SubjectUserName=”SYSTEM” OR SubjectUserName=”LOCAL SERVICE” OR SubjectUserName=”NETWORK SERVICE”) // Filter out common system accounts if noisy  
| sort -count  
| table SubjectUserName, SubjectDomainName, host, Privileges, count

##### Process Creation with Elevated Tokens

Index=Your_Windows_Index EventCode=4648  
| stats values(TargetUserName) as runas_user, values(ProcessName) as source_process, count by AccountName, LogonProcessName, IpAddress, host  
| rename AccountName as initiated_by_user, IpAddress as src_ip  
| sort -count  
| table _time, initiated_by_user, runas_user, source_process, LogonProcessName, src_ip, host

##### User Rights Assignment Changes

Index=Your_Windows_Index (EventCode=4704 OR EventCode=4705)  
| stats values(UserRight) as user_right, values(AccountName) as target_account, values(EventCode) as action_code by SubjectUserName, host  
| eval action = if(action_code=4704, “Assigned”, “Removed”)  
| table _time, SubjectUserName, target_account, user_right, action, host

#### Linux

##### Successful sudo to Root or Other Privileged User

Index=Your_Linux_Index (sourcetype=linux_secure OR sourcetype=syslog) sudo “COMMAND=”  
| rex “USER=(?<target_user>\S+)\s+.*COMMAND=(?<command>.+)”  
| rex “(?<original_user>\S+)\s+: TTY”  
| where target_user=”root” OR target_user=”admin_user_example” // Add other privileged users  
| stats count, values(command) as commands by original_user, target_user, host  
| sort -count  
| table original_user, target_user, host, commands, count

##### Successful su to Root or Other Privileged User

Index=Your_Linux_Index (sourcetype=linux_secure OR sourcetype=syslog) “su: pam_unix(su:session): session opened for user”  
| rex “session opened for user (?<target_user>\S+) by (?<original_user>\S+)\(“  
| where target_user=”root” OR target_user=”admin_user_example” // Add other privileged users  
| stats count by original_user, target_user, host  
| sort -count  
| table original_user, target_user, host, count

##### Changes to /etc/sudoers or Sudoers Drop-in Files

Index=Your_Linux_Index (sourcetype=fim_logs OR sourcetype=ossec OR sourcetype=wazuh) (file_path=”/etc/sudoers” OR file_path=”/etc/sudoers.d/*”) (action=”modified” OR action=”created” OR action=”deleted”)  
| stats values(action) as actions, count by file_path, user, host, _time  
| sort -_time  
| table _time, file_path, actions, user, host, count

##### New User Creation with UID 0 (Root Equivalent)

Index=Your_Linux_Index (sourcetype=linux_audit OR sourcetype=syslog) (executed_command=”useradd * -o -u 0” OR executed_command=”useradd * -u 0 -o”) OR (type=USER_MGMT msg=*new user*)  
// If using auditd, look for syscalls related to /etc/passwd modification by useradd or similar tools and check UID.  
// A simpler approach if you have command line logging:  
// index=Your_Linux_Index (sourcetype=linux_secure OR sourcetype=syslog) sudo “COMMAND=/usr/sbin/useradd”  
// | search COMMAND=”* -u 0 *” OR COMMAND=”* --uid 0 *”  
| rex “COMMAND=(?<command_line>.*useradd.*)”  
| search command_line=”*-u 0*” OR command_line=”*--uid 0*”  
| stats count by user, host, command_line  
| sort -count  
| table user, host, command_line, count

OR

Index=Your_Linux_Index (sourcetype=linux_secure OR sourcetype=syslog) “new user:”  
| rex “new user: name=(?<new_user>\S+), UID=(?<new_uid>\d+), GID=(?<new_gid>\d+), home=(?<new_home>\S+)”  
| where new_uid == 0  
| stats count by new_user, new_uid, new_gid, new_home, host, _raw // _raw can give context of who added  
| sort -_time  
| table _time, new_user, new_uid, host, _raw

## Endpoint Protection and Vulnerability Management Dashboard

### Endpoint Security Controls Status

#### Windows

##### Antivirus/Anti-malware Service Status

Index=Your_Windows_Index sourcetype=”WinEventLog:System” EventCode=7036  
| eval ServiceName=param1, ServiceState=param2  
| search ServiceName=”WinDefend” OR ServiceName=”MsMpEng” // MsMpEng is Microsoft Antimalware Service  
| dedup host sortby -_time  
| where ServiceState=”stopped”  
| table _time, host, ServiceName, ServiceState

##### Firewall Status (Windows Firewall)

Index=Your_Windows_Index sourcetype=”WinEventLog:Microsoft-Windows-Windows Firewall With Advanced Security/Firewall” EventCode=2003 (*profile*is*off*) 
| rex field=_raw “Profile (?<profile>\w+) is now off.”  
| dedup host, profile sortby -_time  
| table _time, host, profile, Message

##### Disk Encryption Status (BitLocker)

Index=Your_Windows_Index sourcetype=”WinEventLog:Microsoft-Windows-BitLocker-DrivePreparationTool/Admin” OR sourcetype=”your_epp_inventory_sourcetype” EventCode=853 OR (source=”epp_inventory” encryption_status=”off”)  
// EventID 853: BitLocker Drive Encryption recovery information for volume C: was successfully backed up to Active Directory Domain Services. (Indicates it was enabled)  
// Look for absence of recent ‘enabled’ events or explicit ‘disabled/suspended’ status from EPP.  
// This is a harder one without dedicated EPP inventory data.  
// A simpler start could be looking for errors in BitLocker logs.  
| search EventCode=XYZ_BitLocker_Error_Code OR (sourcetype=”epp_data” bitlocker_status=”Error” OR bitlocker_status=”Disabled”)  
| stats count by host, bitlocker_status, Message  
| table host, bitlocker_status, Message

##### EDR Agent Health/Status

Index=Your_EDR_Index sourcetype=”your_edr_agent_health_sourcetype”  
| dedup host sortby -_time  
| where agent_status=”Error” OR agent_status=”Not Reporting” OR last_seen < relative_time(now(), “-1h”) // Agent hasn’t checked in for an hour  
| table _time, host, agent_status, last_seen, agent_version  

#### Linux

##### Antivirus Service Status

Index=Your_Linux_Index sourcetype=linux_ps (COMMAND=”clamd” OR COMMAND=”clamav-daemon”)  
| stats dc(host) as reporting_hosts by COMMAND  
// More effectively, look for absence or “stopped” messages in syslog for the service  
// index=Your_Linux_Index sourcetype=syslog (host=* systemd OR host=* service) (“clamav-daemon.service: Succeeded” OR “Stopped Clam AntiVirus Daemon”)  
// | dedup host sortby -_time  
// | where _raw matches “Stopped” OR _raw matches “Failed”  
// | table _time, host, process_name, message  
// This is better done with a heartbeat/health check from the EPP/AV solution itself if available.  
// For a basic check if it’s *ever* reported as stopped recently:
Index=Your_Linux_Index (sourcetype=syslog OR sourcetype=linux_messages) (“clamd” OR “clamav-daemon”) (stopped OR failed OR “activating process exited”)  
| stats earliest(_time) as first_occurrence, latest(_time) as last_occurrence, values(MESSAGE) as messages by host, process_name  
| table host, process_name, last_occurrence, messages

##### Firewall Status

Index=Your_Linux_Index sourcetype=syslog (host=* systemd OR host=* service) “firewalld.service”  
| dedup host sortby -_time  
| where _raw matches “inactive \(dead\)” OR _raw matches “failed” OR _raw matches “Stopped”  
| table _time, host, process_name, Message

##### EDR Agent Health/Status

Index=Your_EDR_Index sourcetype=”your_linux_edr_agent_health_sourcetype” os_type=”Linux”  
| dedup host sortby -_time  
| where agent_status=”Error” OR agent_status=”Not Reporting” OR last_seen < relative_time(now(), “-1h”)  
| table _time, host, agent_status, last_seen, agent_version

##### SELinux/AppArmor Status

Index=Your_Auditd_Index sourcetype=linux_audit type=AVC msg=* // AVC denials indicate SELinux is active. Absence of these on a system supposed to have them could be an issue, or it's permissive.  
// More direct way is if you log ‘getenforce’ or ‘sestatus’ output periodically:  
// index=Your_Linux_Index sourcetype=linux_commands command=”getenforce”  
// | dedup host sortby -_time  
// | where output!=”Enforcing”  
// | table _time, host, output  
// For AppArmor (from syslog/kern.log):  
Index=Your_Linux_Index sourcetype=syslog (kernel AND (AppArmor AND (status OR profile)))  
| rex “apparmor=\”(?<apparmor_status>\w+)\”.*profile=\”(?<apparmor_profile>[^\”]+)\””  
| search apparmor_status=”DENIED” // or look for startup messages indicating mode  
| stats count by host, apparmor_profile, apparmor_status  
| table host, apparmor_profile, apparmor_status, count

### Active Threats

#### Windows and Linux

##### High Severity EPP/EDR Alerts

Index=Your_EDR_Index OR index=Your_EPP_Index (severity=”high” OR severity=”critical” OR priority=”high” OR priority=”critical”)  
| stats count by _time, host, rule_name, signature, threat_name, user, process_name, action_taken  
| sort -_time  
| table _time, host, rule_name, signature, threat_name, user, process_name, action_taken, count

##### Confirmed Malicious File/Process Detections (Behavioral)

Index=Your_EDR_Index detection_type=”behavioral” (disposition=”malicious” OR threat_status=”active” OR confirmed_threat=”true”)  
| stats earliest(_time) as first_seen, latest(_time) as last_seen, values(process_path) as suspicious_processes, values(command_line) as cmd_lines by host, threat_name, detection_id  
| sort -last_seen  
| table host, threat_name, first_seen, last_seen, suspicious_processes, cmd_lines

##### Potential Ransomware Activity Indicators

Index=Your_Sysmon_Index EventCode=1 (process_name=”vssadmin.exe” AND command_line=”*delete shadows*”) OR (process_name=”wbadmin.exe” AND command_line=”*delete catalog*”)  
| stats count by _time, host, user, process_name, command_line  
| sort -_time  
| table _time, host, user, process_name, command_line, count  
// Add EDR specific ransomware detection names:  
// OR (index=Your_EDR_Index (threat_name=”*Ransomware*” OR rule_name=”*Ransomware*” OR category=”Ransomware”))

### Missing Patches

#### Windows

##### Hosts with Missing Critical/High Security Patches (from Vulnerability Scanner or WSUS logs)

Index=Your_Vuln_Index (severity=”Critical” OR severity=”High”) (patch_status=”missing” OR state=”Vulnerable”) os=”Windows”  
| stats dc(vulnerability_title) as missing_critical_high_patches_count, values(vulnerability_title) as vulnerabilities by host  
| sort -missing_critical_high_patches_count  
| table host, missing_critical_high_patches_count, vulnerabilities

##### Specific Important KB Missing

// Using vulnerability scanner data is more reliable  
Index=Your_Vuln_Index os=”Windows” (vulnerability_id=”MSXX-XXX” OR kb_id=”KBXXXXXXX” OR cve=”CVE-XXXX-XXXXX”) (patch_status=”missing” OR state=”Vulnerable”)  
| stats values(patch_solution) as solution by host, vulnerability_title  
| table host, vulnerability_title, solution  
// If you have a list of installed patches per host:  
// index=patch_inventory sourcetype=windows_installed_patches host=*  
// | stats values(KBID) as installed_kbs by host  
// | search NOT installed_kbs=”KB5001234” // The KB you are looking for  
// | table host

#### Linux

##### Hosts with Outdated Security Packages (from Vulnerability Scanner)

Index=Your_Vuln_Index (severity=”Critical” OR severity=”High”) (patch_status=”missing” OR state=”Vulnerable”) (os=”Linux” OR os_distro=”Ubuntu” OR os_distro=”CentOS” OR os_distro=”RedHat”)  
| stats dc(vulnerability_title) as missing_security_updates_count, values(package_name) as packages by host  
| sort -missing_security_updates_count  
| table host, missing_security_updates_count, packages

### Endpoint Detection and Response (EDR) Specific Alerts

#### Windows and Linux

##### Suspicious Process Execution (e.g., LOLBAS, PowerShell encoding)

Index=Your_Sysmon_Index EventCode=1 (process_name=”powershell.exe” AND (command_line=”* -enc *” OR command_line=”* -EncodedCommand *” OR command_line=”* -nop -exec bypass *”)) OR (process_name IN (“certutil.exe”, “regsvr32.exe”, “mshta.exe”, “rundll32.exe”) AND command_line=”*-urlcache*” OR command_line=”*/s*http*”)  
| stats count by _time, host, user, process_name, command_line, parent_process_name  
| sort -_time  
| table _time, host, user, process_name, command_line, parent_process_name, count

##### Detected Lateral Movement (e.g., PsExec, WMI remote execution, SSH from unusual source)

Index=Your_Sysmon_Index EventCode=1 process_name=”PSEXESVC.exe”  
| stats count by _time, host, user, parent_process_name  
| sort -_time  
| table _time, host, user, parent_process_name, count  
// For WMI remote process creation (EventCode=1, ParentImage ending in WmiPrvSE.exe, and process not usually child of WmiPrvSE)  

Index=Your_Sysmon_Index EventCode=1 ParentImage=”C:\\Windows\\System32\\wbem\\WmiPrvSE.exe” NOT process_name IN (“trusted_child1.exe”, “trusted_child2.exe”)
| stats count by _time, host, user, process_name, command_line, ParentImage
| sort -_time
| table _time, host, user, process_name, command_line, ParentImage, count

##### SSH from internal host to another internal host NOT typical jump server

Index=Your_Linux_Index (sourcetype=linux_secure OR sourcetype=syslog) “Accepted publickey for” OR “Accepted password for”  
| rex “Accepted \S+ for (?<user>\S+) from (?<src_ip>\S+) port \d+ ssh2”  
| where isnotnull(src_ip) AND src_ip!=”EXTERNAL_GATEWAY_IP” AND src_ip!=”KNOWN_ADMIN_WORKSTATION_IP_RANGE”  
| stats count by src_ip, user, dest_host // dest_host is the logging server  
| where count > 5 // Tune threshold  
| sort -count  
| table src_ip, user, dest_host, count

##### Credential Dumping Attempts (e.g., LSASS access, mimikatz patterns)

Index=Your_Sysmon_Index EventCode=10 TargetImage=”C:\\Windows\\System32\\lsass.exe” CallTrace=”*dbgcore.dll*” OR CallTrace=”*dbghelp.dll*” NOT (SourceImage=”C:\\Windows\\System32\\svchost.exe” OR SourceImage=”C:\\Windows\\System32\\taskmgr.exe”) // Filter known good ones  
| stats count by _time, host, SourceImage, TargetImage, GrantedAccess  
| sort -_time  
| table _time, host, SourceImage, TargetImage, GrantedAccess, count  
// Or from EDR:  
// index=Your_EDR_Index (rule_name=”*Mimikatz*” OR rule_name=”*LSASS*” OR threat_name=”*CredentialTheft*”)

##### Suspicious file access to shadow/passwd, or auditd logs for specific syscalls if EDR doesn’t cover

Index=Your_Auditd_Index sourcetype=linux_audit type=SYSCALL (path=”/etc/shadow” OR path=”/etc/passwd”) (syscall=openat OR syscall=open) perm=r key=”sensitive_file_access” NOT (exe=”/usr/bin/passwd” OR exe=”/usr/sbin/unix_chkpwd”)  
| stats count by _time, host, auid, exe, path  
| sort -_time  
| table _time, host, auid, exe, path, count

### Virus and Malware

#### Windows and Linux

### Vulnerability Scanner

### Policy Infraction

## System Integrity and Anomaly Detection Dashboard

### OS

### File Integrity Monitoring

### HIDS Alerts

### Basic Performance Metrics
