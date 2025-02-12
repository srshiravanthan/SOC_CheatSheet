# Detecting Common User/Domain Recon

## **User/Domain Reconnaissance Using Native Windows Executables**

```
commands
1. net group "Dmain Admins" /domain
2 .whoami /all
3. wmic computersystem get domain
4. net user /domain
5. net group "Domain Admins" /domain
6. arp -a
7. nltest /domain_trusts
```

**User/Domain Reconnaissance Using BloodHound/SharpHound**

```
1. ./sharphound3.exe -c all
```

## **Detecting Recon By Targeting Native Windows Executables**

```
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 earliest=1690447949 latest=1690450687
| search process_name IN (arp.exe,chcp.com,ipconfig.exe,net.exe,net1.exe,nltest.exe,ping.exe,systeminfo.exe,whoami.exe) OR (process_name IN (cmd.exe,powershell.exe) AND process IN (*arp*,*chcp*,*ipconfig*,*net*,*net1*,*nltest*,*ping*,*systeminfo*,*whoami*))
| stats values(process) as process, min(_time) as _time by parent_process, parent_process_id, dest, user
| where mvcount(process) > 3
```

## **Detecting Recon By Targeting BloodHound**

```
index=main earliest=1690195896 latest=1690285475 source="WinEventLog:SilkService-Log"
| spath input=Message 
| rename XmlEventData.* as * 
| table _time, ComputerName, ProcessName, ProcessId, DistinguishedName, SearchFilter
| sort 0 _time
| search SearchFilter="*(samAccountType=805306368)*"
| stats min(_time) as _time, max(_time) as maxTime, count, values(SearchFilter) as SearchFilter by ComputerName, ProcessName, ProcessId
| where count > 10
| convert ctime(maxTime)
```
