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

### Endpoint Security Controls

### Active Threats

### Missing Patches

### Endpoint Detection and Response

### Virus and Malware

### Vulnerability Scanner

### Policy Infraction

## System Integrity and Anomaly Detection Dashboard

### OS

### File Integrity Monitoring

### HIDS Alerts

### Basic Performance Metrics
