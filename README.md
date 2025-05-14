# Standard Splunk SOC Dashboards

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

### Failed SSH Logins with Non-Existent Usernames

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
