# Log Analysis Report

## Overview

This report analyzes SSH authentication logs using the Threat Detect CLI tool to identify potential security threats such as brute-force attacks, user enumeration, and scanning activity.

---

## Detected Attacks

### 1. Brute Force Attack (T1110)

Multiple IP addresses triggered repeated failed login attempts.

Example:
- IP: 190.178.62.6
- Behavior: Multiple "maximum authentication attempts exceeded"

Reason:
Repeated login failures indicate automated password guessing attempts.

Severity: HIGH

---

### 2. User Enumeration (T1087)

Attackers attempted to discover valid usernames.

Example:
- IP: 201.177.23.130
- Activity: "Invalid user admin"

Reason:
Trying common usernames to identify valid accounts.

Severity: MEDIUM

---

### 3. Scanning Activity (T1046)

Suspicious connection attempts detected.

Example:
- "Did not receive identification string"
- "Bad protocol version"

Reason:
Indicates probing or scanning of SSH service.

Severity: LOW

---

## High-Risk IPs

IPs involved in multiple attack types:

- 190.178.62.6
- 85.245.107.41

These represent more advanced or persistent attackers.

---

## Conclusion

The log data shows clear signs of automated attacks targeting SSH services, including brute-force attempts and reconnaissance activity. 

The Threat Detect tool successfully identifies and classifies these threats using MITRE ATT&CK mapping and severity scoring.

---

## Recommendations

- Disable password-based SSH login
- Use key-based authentication
- Enable fail2ban or similar protection
- Monitor logs continuously
