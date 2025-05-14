# Standard Splunk SOC Dashboards

## Systems Security Posture Dashboard

### Critical Alerts

### High/Critical Unpatched Vulnerabilities

### Active Endpoint Detections

### Alert/Detection Statistics

## Authentication and Access Management Dashboard

### Suspicious Login Activity

##### Windows

Index=Your_Windows_Index EventCode=4625 OR EventCode=4624 action=failure OR action=success
| stats count(eval(EventCode=4625)) as failed_logins, count(eval(EventCode=4624)) as successful_logins, earliest(_time) as first_attempt, latest(_time) as last_attempt by user, src_ip
| where failed_logins > 5 AND successful_logins > 0 AND (last_attempt – first_attempt) < 1800  // Adjust failed_logins threshold and time window (1800 seconds = 30 minutes) as needed
| sort -failed_logins
| table user, src_ip, failed_logins, successful_logins, first_attempt, last_attempt

### Logins from Unusual Geographic Locations

#### Windows

Index=Your_Windows_Index EventCode=4624 action=success
| iplocation src_ip
| search NOT (Country=”Your_Expected_Country_1” OR Country=”Your_Expected_Country_2”) // Add your expected countries
| stats count by user, src_ip, City, Country
| sort -count
| table user, src_ip, City, Country, count

### Login Outside of Business Hours

#### Windows

Index=Your_Windows_Index EventCode=4624 action=success
| eval hour = strftime(_time, “%H”)
| where hour < 8 OR hour > 18 // Adjust hours as per your business schedule (e.g., < 8 AM or > 6 PM)
| eval day_of_week = strftime(_time, “%w”) // 0=Sunday, 6=Saturday
| where day_of_week != 0 AND day_of_week != 6 // Exclude weekends if needed
| stats count by user, src_ip, _time, host
| sort -_time
| table user, src_ip, _time, host, count

### Concurrent Logins from Different IPs for the Same User

#### Windows

Index=Your_Windows_Index EventCode=4624 action=success
| stats dc(src_ip) as distinct_ips, values(src_ip) as source_ips, earliest(_time) as first_login, latest(_time) as last_login by user
| where distinct_ips > 1 AND (last_login – first_login) < 3600 // Adjust time window (3600 seconds = 1 hour) as needed
| sort -distinct_ips
| table user, distinct_ips, source_ips, first_login, last_login

### Unauthorized Access Attempts

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
