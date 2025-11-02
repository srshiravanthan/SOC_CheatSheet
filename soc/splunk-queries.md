---
layout:
  width: wide
  title:
    visible: true
  description:
    visible: false
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
  metadata:
    visible: true
---

# Splunk Queries

1.  Query to identify failed login attempts:

    ```
    sourcetype=auth* "authentication failure"
    | stats count by user
    | sort -count
    ```
2.  Query to identify potential security threats:

    ```
    sourcetype=access_* method=POST status=200 | rex field=_raw "password=(?[^&]+)"
    | eval password_length=length(password)
    | where password_length >= 8
    ```
3.  Query to identify privilege escalation attempts:

    ```
    sourcetype=linux_secure su*
    | where user!=root AND user!=""
    ```
4.  Query to identify failed SSH attempts:

    ```
    sourcetype=linux_secure "Failed password for"
    | stats count by src_ip
    | sort -count
    ```
5.  Query to identify successful SSH attempts:

    ```
    sourcetype=linux_secure "Accepted publickey for"
    | stats count by src_ip
    | sort -count
    ```
6.  Query to identify unusual network traffic:

    ```
    sourcetype=network_traffic
    | stats sum(bytes) as total_bytes by src_ip, dest_ip
    | where total_bytes > 1000000
    ```
7.  Query to identify suspicious processes:

    ```
    sourcetype=processes
    | search "lsass.exe" OR "svchost.exe" OR "explorer.exe"
    | stats count by user
    | sort -count
    ```
8.  Query to identify brute force attacks:

    ```
    sourcetype=access_* | stats count by clientip, action | where action="failure" AND count>=5
    ```
9.  Query to identify privilege escalation attempts on Windows systems:

    ```
    sourcetype="WinEventLog:Security" EventCode=4672
    | eval user_account=mvindex(Account_Name,1)
    | search "Security ID" NOT IN ("SYSTEM","LOCAL SERVICE","NETWORK SERVICE")
    ```
10. Query to identify abnormal user activity:

    ```
    sourcetype=access_* action=purchase
    | stats count by clientip, user
    | where count > 50
    ```
