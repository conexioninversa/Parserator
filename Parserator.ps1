cls
<#

██████╗  █████╗ ██████╗ ███████╗███████╗██████╗  █████╗ ████████╗ ██████╗ ██████╗ 
██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
██████╔╝███████║██████╔╝███████╗█████╗  ██████╔╝███████║   ██║   ██║   ██║██████╔╝
██╔═══╝ ██╔══██║██╔══██╗╚════██║██╔══╝  ██╔══██╗██╔══██║   ██║   ██║   ██║██╔══██╗
██║     ██║  ██║██║  ██║███████║███████╗██║  ██║██║  ██║   ██║   ╚██████╔╝██║  ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
                                                                                  

 "************************************************************"  
 "          Pedro Sánchez Cordero - Conexioninversa  (2021)   "   
 "************************************************************"  
Se necesita los EVTX.
Luego ejecuta parserator.ps1 y se feliz como Raúl

Se necesita los SIGUIENTES evtx: 

Microsoft-Windows-TaskScheduler%4Operational.evtx
Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Admin.evtx
Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx
Security.evtx
System.evtx

Luego ejecuta parserator.ps1 y se feliz.(Dedicado a Yovana Rodriguez)
 
  
#>

Write-Host  " " 
Write-Host  " " 
Write-Host  " "
Write-Host " _____  _______  ______ _______ _______  ______ _______ _______  _____   ______  " -ForegroundColor green 
Write-Host "|_____] |_____| |_____/ |______ |______ |_____/ |_____|    |    |     | |_____/  " -ForegroundColor green 
Write-Host "|       |     | |    \_ ______| |______ |    \_ |     |    |    |_____| |    \_  " -ForegroundColor green 
Write-Host "                                                                                 " 
Write-Host  " " 
Write-Host "*********************************************************************************"  
Write-Host "                       SANTANDER GLOBAL FORENSICS TEAM                           "   
Write-Host "*********************************************************************************"  
Write-Host  " "  
Write-Host  "                            - EVTX Analysis -                                   "                                                           
Write-Host  " "                                                    
Write-Host  " "
Write-Host  " "
Write-Host  "**********************************************"  -ForegroundColor red -BackgroundColor white
Write-Host  "             System Log                      *"  -ForegroundColor red -BackgroundColor white
Write-Host  "**********************************************"  -ForegroundColor red -BackgroundColor white
Write-Host  " "
Write-Host  " "
#Write-Host "Find Event id 6006" -ForegroundColor green
Write-Host "Searching for normal shutdown" -ForegroundColor green
Write-Host "Creating file ---> NormalShutdown.csv" -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT  "SELECT TimeGenerated, Timewritten, message INTO NormalShutdown.csv FROM system Where EventID= '6006'" -o:CSV
Write-Host  " "
#Write-Host "Find Event id 6008" -ForegroundColor green
Write-Host "Looking for forced shutdown" -ForegroundColor green
Write-Host "Creating file ---> ForcedShutdown.csv" -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT  "SELECT TimeGenerated, Timewritten, message INTO ForceShutdown.csv FROM system Where EventID= '6008'" -o:CSV
Write-Host  " "
#Write-Host "Find Event id 1001" -ForegroundColor green
Write-Host "Looking for System Crash" -ForegroundColor green
Write-Host "Creating file ---> CrashShutdown.csv" -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT  "SELECT TimeGenerated, Timewritten, message INTO CrashShutdown.csv FROM system Where EventID= '1001'" -o:CSV
Write-Host  " "                                                                          
Write-Host  " "
Write-Host  " "
Write-Host  "**********************************************"  -ForegroundColor red -BackgroundColor white
Write-Host  "             Security Log                    *"  -ForegroundColor red -BackgroundColor white
Write-Host  "**********************************************"  -ForegroundColor red -BackgroundColor white
Write-Host  " "
Write-Host  " "
Write-Host  " "
Write-Host  "Searching for lateral movement " -ForegroundColor green
Write-Host "Creating file ---> LateralMovement.csv" -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 1, '|') AS Username, EXTRACT_TOKEN(Strings, 2, '|') AS Domain, EXTRACT_TOKEN(Strings, 5, '|') AS Process INTO LateralMovement.csv FROM Security.evtx WHERE EventID = 4688 AND Process LIKE '%\\at.exe'  OR Process LIKE '%\\ceipdata.exe'  OR Process LIKE '%\\ceiprole.exe'  OR  Process LIKE '%\\chcp.exe' OR Process LIKE '%\\cmd.exe'  OR Process LIKE '%\\compmgmtlauncher.exe'  OR Process LIKE '%\\csvde.exe'  OR Process LIKE '%\\dsget.exe' OR Process LIKE '%\\dsquery.exe'  OR Process LIKE '%\\esentutl.exe'  OR Process LIKE '%\\\\find.exe'  OR Process LIKE '%\\fsutil.exe'  OR Process LIKE '%\\hostname.exe'  OR Process LIKE '%\\ipconfig.exe'  OR Process LIKE '%\\ldifde.exe'  OR Process LIKE '%\\nbtstat.exe'  OR Process LIKE '%\\net.exe'  OR Process LIKE '%\\net1.exe'  OR Process LIKE '%\\netdom.exe' OR Process LIKE '%\\netsh.exe' OR Process LIKE '%\\netstat.exe' OR Process LIKE '%\\nltest.exe' OR Process LIKE '%\\nslookup.exe' OR Process LIKE '%\\ping.exe' OR Process LIKE '%\\psexec.exe' OR Process LIKE '%\\qprocess.exe' OR Process LIKE '%\\query.exe' OR Process LIKE '%\\quser.exe' OR Process LIKE '%\\qwinsta.exe' OR Process LIKE '%\\reg.exe'  OR Process LIKE '%\\sc.exe' OR Process LIKE '%\\schtasks.exe' OR Process LIKE '%\\servermanagercmd.exe' OR Process LIKE '%\\set.exe' OR Process LIKE '%\\systeminfo.exe' OR Process LIKE '%\\tasklist.exe' OR Process LIKE '%\\time.exe' OR Process LIKE '%\\tracert.exe'  OR Process LIKE '%\\tree.exe' OR Process LIKE '%\\type.exe' OR Process LIKE '%\\vds.exe' OR Process LIKE '%\\vdsldr.exe' OR Process LIKE '%\\ver.exe' OR Process LIKE '%\\wevtutil.exe' OR Process LIKE '%\\whoami.exe' OR Process LIKE '%\\WinrsHost.exe' OR Process LIKE '%\\inver.exe' OR Process LIKE '%\\wmic.exe' OR Process LIKE '%\\wusa.exe' AND NOT Process LIKE '%\\dsregcmd.exe'"
Write-Host  " "
#Write-Host  "Look at NTLM based logons"  -ForegroundColor green 
Write-Host  "find possible pass-the-hash"   -ForegroundColor green
Write-Host "Creating file ---> PassTheHash.csv" -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 5, '|') as Username, EXTRACT_TOKEN(Strings, 6, '|') as Domain, EXTRACT_TOKEN(Strings, 8, '|') as LogonType, EXTRACT_TOKEN(strings, 10, '|') AS AuthPackage, EXTRACT_TOKEN(Strings, 11, '|') AS Workstation, EXTRACT_TOKEN(Strings, 17, '|') AS ProcessName, EXTRACT_TOKEN(Strings, 18, '|') AS SourceIP INTO PassTheHash.csv FROM 'Security.evtx' WHERE EventID = 4624 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Domain NOT IN ('NT AUTHORITY') AND AuthPackage LIKE '%NtLmSsp%' AND Username NOT LIKE '%$'" -o:CSV
Write-Host  " "
Write-Host  " "
#Write-Host  "Eventid 1102"  -ForegroundColor green
Write-Host  "Find Eventlog was cleared"  -ForegroundColor green
Write-Host "Creating file ---> EventlogCleared.csv" -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 1, '|') as Username, EXTRACT_TOKEN(Strings, 2, '|') AS Workstation INTO EventlogCleared.csv FROM 'Security.evtx' WHERE EventID = '1102'"
Write-Host  " "
#Write-Host  "Eventid 4624"  -ForegroundColor green
Write-Host  "successful logon"  -ForegroundColor green
Write-Host  "Creating file ---> SuccessfulLogon.csv"  -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 5, '|') as Username, EXTRACT_TOKEN(Strings, 6, '|') as Domain, EXTRACT_TOKEN(Strings, 8, '|') as LogonType,EXTRACT_TOKEN(strings, 9, '|') AS AuthPackage, EXTRACT_TOKEN(Strings, 11, '|') AS Workstation, EXTRACT_TOKEN(Strings, 17, '|') AS ProcessName, EXTRACT_TOKEN(Strings, 18, '|') AS SourceIP  INTO SuccessfulLogon.csv FROM 'Security.evtx' WHERE EventID = 4624 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Domain NOT IN ('NT AUTHORITY')" -o:CSV
Write-Host  " "
Write-Host  "Find specific IP Admin" -ForegroundColor green 
Write-Host  "Creating file ---> IPLogonAdmin.csv"  -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 5, '|') as Username, EXTRACT_TOKEN(Strings, 6, '|') as Domain, EXTRACT_TOKEN(Strings, 8, '|') as LogonType,EXTRACT_TOKEN(strings, 9, '|') AS AuthPackage, EXTRACT_TOKEN(Strings, 11, '|') AS Workstation, EXTRACT_TOKEN(Strings, 17, '|') AS ProcessName, EXTRACT_TOKEN(Strings, 18, '|') AS SourceIP INTO IPLogonAdmin.csv FROM 'Security.evtx' WHERE EventID = 4624 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Domain NOT IN ('NT AUTHORITY') AND Username = 'Administrador'" -o:CSV
Write-Host  " "
Write-Host  "Find IP RDP logons"  -ForegroundColor green
Write-Host  "Creating file ---> IPLogonRDP.csv"  -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 5, '|') as Username, EXTRACT_TOKEN(Strings, 6, '|') as Domain, EXTRACT_TOKEN(Strings, 8, '|') as LogonType,EXTRACT_TOKEN(strings, 9, '|') AS AuthPackage, EXTRACT_TOKEN(Strings, 11, '|') AS Workstation, EXTRACT_TOKEN(Strings, 17, '|') AS ProcessName, EXTRACT_TOKEN(Strings, 18, '|') AS SourceIP INTO IPLogonRDP.csv FROM 'Security.evtx' WHERE EventID = 4624 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Domain NOT IN ('NT AUTHORITY') AND LogonType = '10'" -o:CSV
Write-Host  " "
Write-Host  "Find console logons" -ForegroundColor green 
Write-Host  "Creating file ---> ConsoleLogon.csv" -ForegroundColor green 
.\LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 5, '|') as Username, EXTRACT_TOKEN(Strings, 6, '|') as Domain, EXTRACT_TOKEN(Strings, 8, '|') as LogonType,EXTRACT_TOKEN(strings, 9, '|') AS AuthPackage, EXTRACT_TOKEN(Strings, 11, '|') AS Workstation, EXTRACT_TOKEN(Strings, 17, '|') AS ProcessName, EXTRACT_TOKEN(Strings, 18, '|') AS SourceIP INTO ConsoleLogon.csv FROM 'Security.evtx' WHERE EventID = 4624 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Domain NOT IN ('NT AUTHORITY') AND LogonType = '2'" -o:CSV
Write-Host  " "
#Write-Host  "Find specific IP"  -ForegroundColor green
#.\LogParser.exe -stats:OFF -i:EVT   "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 5, '|') as Username, EXTRACT_TOKEN(Strings, 6, '|') as Domain, EXTRACT_TOKEN(Strings, 8, '|') as LogonType,EXTRACT_TOKEN(strings, 9, '|') AS AuthPackage, EXTRACT_TOKEN(Strings, 11, '|') AS Workstation, EXTRACT_TOKEN(Strings, 17, '|') AS ProcessName, EXTRACT_TOKEN(Strings, 18, '|') AS SourceIP FROM 'Security.evtx' WHERE EventID = 4624 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Domain NOT IN ('NT AUTHORITY') AND SourceIP = '192.168.1.68'"
#Write-Host  " "
#Write-Host  "Event id 4625"  -ForegroundColor green
Write-Host  "unsuccessful logon"  -ForegroundColor green
Write-Host  "Creating file ---> UnsuccessfulLogon.csv" -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 5, '|') as Username, EXTRACT_TOKEN(Strings, 6, '|') as Domain, EXTRACT_TOKEN(Strings, 10, '|') as LogonType,EXTRACT_TOKEN(strings, 11, '|') AS AuthPackage, EXTRACT_TOKEN(Strings, 13, '|') AS Workstation, EXTRACT_TOKEN(Strings, 19, '|') AS SourceIP INTO UnsuccessfulLogon.csv FROM 'Security.evtx' WHERE EventID = 4625 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Domain NOT IN ('NT AUTHORITY')" -o:CSV
Write-Host  " "
#Write-Host  "event id 4634"  -ForegroundColor green
Write-Host  "User logoff"  -ForegroundColor green
Write-Host  "Creating file ---> UserLogoff.csv" -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT "Select TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 1, '|') AS Username, EXTRACT_TOKEN(Strings, 2, '|') AS Domain INTO UserLogoff.csv FROM 'Security.evtx' WHERE EventID = 4634 AND Domain NOT IN ('NT AUTHORITY')" -o:CSV
Write-Host  " "
#Write-Host  "Event id 4648" -ForegroundColor green 
Write-Host  "Explicit creds was use"  -ForegroundColor green
Write-Host  "Creating file ---> ExplicitCreds.csv"  -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT "SELECT timegenerated as date, extract_token(strings, 1, '|') as accountname, extract_token(strings, 2, '|') as domain, extract_token(strings, 5, '|') as usedaccount, extract_token(strings, 6, '|') as useddomain, extract_token(strings, 8, '|') as targetserver, extract_token(strings, 9, '|') as extradata, extract_token(strings, 11, '|') as procname, extract_token(strings, 12, '|') as sourceip INTO ExplicitCreds.csv from 'Security.evtx' WHERE EventID = 4648" -o:CSV
Write-Host  " "
#Write-Host  "Search by accountname"  -ForegroundColor green
#.\LogParser.exe -stats:OFF -i:EVT   "SELECT timegenerated as date, extract_token(strings, 1, '|') as accountname, extract_token(strings, 2, '|') as domain, extract_token(strings, 5, '|') as usedaccount, extract_token(strings, 6, '|') as useddomain, extract_token(strings, 8, '|') as targetserver, extract_token(strings, 9, '|') as extradata, extract_token(strings, 11, '|') as procname, extract_token(strings, 12, '|') as sourceip from 'Security.evtx' WHERE EventID = 4648 AND accountname = 'Administrator'"
#Write-Host  " "
#Write-Host  "Search by usedaccount" -ForegroundColor green 
#.\LogParser.exe -stats:OFF -i:EVT   "SELECT timegenerated as date, extract_token(strings, 1, '|') as accountname, extract_token(strings, 2, '|') as domain, extract_token(strings, 5, '|') as usedaccount, extract_token(strings, 6, '|') as useddomain, extract_token(strings, 8, '|') as targetserver, extract_token(strings, 9, '|') as extradata, extract_token(strings, 11, '|') as procname, extract_token(strings, 12, '|') as sourceip from 'Security.evtx' WHERE EventID = 4648 AND usedaccount = 'Administrator'"
#Write-Host  " "

#Write-Host  "event id 4657"  -ForegroundColor green
Write-Host  "A registry value was modified" -ForegroundColor green 
Write-Host  "Creating file ---> RegistryModified.csv"  -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT "SELECT * INTO RegistryModified.csv FROM 'Security.evtx' WHERE EventID = '4657'" -o:CSV
Write-Host  " "

#Write-Host  "event id 4663" -ForegroundColor green 
Write-Host  "An attempt was made to access an object"  -ForegroundColor green
Write-Host  "Creating file ---> AttempAccessObject.csv"  -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT "SELECT * INTO AttempAccessObject.csv FROM 'Security.evtx' WHERE EventID = '4663'" -o:CSV
Write-Host  " "
#Write-Host  "Event id 4672" -ForegroundColor green 
Write-Host  "Admin logon" -ForegroundColor green 
Write-Host  "Creating file ---> AdminLogonCreated.csv"  -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT "Select TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 1, '|') AS Username, EXTRACT_TOKEN(Strings, 2, '|') AS Domain INTO AdminLogonCreated.csv FROM 'Security.evtx' WHERE EventID = 4672 AND Domain NOT IN ('NT AUTHORITY')" -o:CSV
Write-Host  " "
#Write-Host  "event id 4688" -ForegroundColor green 
Write-Host  "Searching new process was created" -ForegroundColor green 
Write-Host  "Creating file ---> NewProcess.csv"  -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 1, '|') AS Username, EXTRACT_TOKEN(Strings, 2, '|') AS Domain, EXTRACT_TOKEN(Strings, 5, '|') AS Process INTO NweProcess.csv FROM 'Security.evtx' WHERE EventID = 4688" -o:CSV
Write-Host  " "
#Write-Host  "Search by user" -ForegroundColor green 
#.\LogParser.exe -stats:OFF -i:EVT   "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 1, '|') AS Username, EXTRACT_TOKEN(Strings, 2, '|') AS Domain, EXTRACT_TOKEN(Strings, 5, '|') AS Process FROM 'Security.evtx' WHERE EventID = 4688 AND Username = 'Administrator'"
#Write-Host  " "
#Write-Host  "Search by process name" -ForegroundColor green 
#.\LogParser.exe -stats:OFF -i:EVT   "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 1, '|') AS Username, EXTRACT_TOKEN(Strings, 2, '|') AS Domain, EXTRACT_TOKEN(Strings, 5, '|') AS Process FROM 'Security.evtx' WHERE EventID = 4688 AND Process LIKE '%rundll32.exe%'"
#Write-Host  " "
#Write-Host  "group by username" -ForegroundColor green 
#.\LogParser.exe -stats:OFF -i:EVT   "SELECT COUNT(*) AS CNT, EXTRACT_TOKEN(Strings, 1, '|') AS Username FROM 'Security.evtx' WHERE EventID = 4688 GROUP BY Username ORDER BY CNT DESC"
#Write-Host  " "
#Write-Host  "group by process name" -ForegroundColor green 
#.\LogParser.exe -stats:OFF -i:EVT   "SELECT COUNT(*) AS CNT, EXTRACT_TOKEN(Strings, 5, '|') AS Process FROM 'Security.evtx' WHERE EventID = 4688 GROUP BY Process ORDER BY CNT DESC"
#Write-Host  " "
#Write-Host  "event id 4704" -ForegroundColor green 
Write-Host  "A user right was assigned" -ForegroundColor green 
Write-Host  "Creating file ---> Userright.csv"  -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT "SELECT *INTO Userright.csv FROM 'Security.evtx' WHERE EventID = '4704'" -o:CSV
Write-Host  " "
#Write-Host  "event id 4705"  -ForegroundColor green
Write-Host  "A user right was"-ForegroundColor green
Write-Host  "Creating file ---> UserRightWas.csv"  -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT "SELECT * INTO UserRightWas.csv FROM 'Security.evtx' WHERE EventID = '4705'" -o:CSV
Write-Host  " "
#Write-Host  "event id 4720" -ForegroundColor green 
Write-Host  "A user account was created" -ForegroundColor green 
Write-Host  "Creating file ---> AccountCreated.csv"  -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(Strings, 0, '|') AS createduser, extract_token(strings, 1, '|') AS createddomain, extract_token(strings, 4, '|') as whocreated, extract_token(strings, 5, '|') AS whodomain INTO AccountCreated.csv FROM 'Security.evtx' WHERE EventID = '4720'" -o:CSV
Write-Host  " "

#Write-Host  "Event id 4722"-ForegroundColor green  
Write-Host  "user account was enabled" -ForegroundColor green 
Write-Host  "Creating file ---> AccountWasEnabled.csv"  -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain INTO AccountWasEnabled.csv FROM 'Security.evtx' WHERE EventID = 4722" -o:CSV
Write-Host  " "
#Write-Host  "event id 4723" -ForegroundColor green 
Write-Host  "attempt to change password for the account - user changed his on password" -ForegroundColor green
Write-Host  "Creating file ---> ChangePassword.csv"  -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain INTO ChangePassword.csv FROM 'Security.evtx' WHERE EventID = 4723" -o:CSV
Write-Host  " "

#Write-Host  "event id 4724" -ForegroundColor green 
Write-Host  "attempt to reset user" -ForegroundColor green
Write-Host  "Creating file ---> ResetUser.csv"  -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain INTO ResetUser.csv FROM 'Security.evtx' WHERE EventID = 4724" -o:CSV
Write-Host  " "
#Write-Host  "event id 4725" -ForegroundColor green  
Write-Host  "user account was disabled" -ForegroundColor green 
Write-Host  "Creating file ---> Accountdisabled.csv"  -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain INTO Accountdisabled.csv FROM 'Security.evtx' WHERE EventID = 4725" -o:CSV
Write-Host  " "
#Write-Host  "event id 4726"  -ForegroundColor green
Write-Host  "A user account was deleted" -ForegroundColor green  
Write-Host  "Creating file ---> AccountDeleted.csv"  -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(Strings, 0, '|') AS deleteduser, extract_token(strings, 1, '|') AS deleteddomain, extract_token(strings, 4, '|') as whodeleted, extract_token(strings, 5, '|') AS whodomain INTO AccountDeleted.csv FROM 'Security.evtx' WHERE EventID = '4726'" -o:CSV
Write-Host  " "
#Write-Host  "event id 4738" -ForegroundColor green 
Write-Host  "user account was changed"   -ForegroundColor green
Write-Host  "Creating file ---> AccountChanged.csv"  -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 1, '|') as user, extract_token(strings, 2, '|') as domain, extract_token(strings, 5, '|') as whichaccount, extract_token(strings, 6, '|') as whichdomain INTO AccountChanged.csv FROM 'Security.evtx' WHERE EventID = 4738" -o:CSV
Write-Host  " "
######
# Write-Host  "event id 4740" -ForegroundColor green 
Write-Host  "A user account was locked out" -ForegroundColor green 
Write-Host  "Creating file ---> AccountLockedOut.csv"  -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as workstation, extract_token(strings, 4, '|') as wholocked, extract_token(strings, 5, '|') as whodomain INTO AccountLockedOut.csv FROM 'Security.evtx' WHERE EventID = '4740'" -o:CSV
Write-Host  " "
#Write-Host  "event id 4742" -ForegroundColor green 
Write-Host  "computer account was changed" -ForegroundColor green  
Write-Host  "Creating file ---> ComputerChanged.csv"  -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 5, '|') as user, extract_token(strings, 6, '|') as domain, extract_token(strings, 1, '|') as whichaccount, extract_token(strings, 2, '|') as whichdomain INTO ComputerChanged.csv FROM 'Security.evtx' WHERE EventID = 4742" -o:CSV
Write-Host  " "
#Write-Host  "event id 4767" -ForegroundColor green 
Write-Host  "A user account was unlocked" -ForegroundColor green 
Write-Host  "Creating file ---> AccountUnlocked.csv"  -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT "SELECT * INTO AccountUnlocked.csv FROM 'Security.evtx' WHERE EventID = '4767'" -o:CSV
Write-Host  " "
#Write-Host  "event id 4776" -ForegroundColor green 
Write-Host  "domain/computer attemped to validate user credentials" -ForegroundColor green 
Write-Host  "Creating file ---> ComputerToValidate.csv"  -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT "Select TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 1, '|') AS Username, EXTRACT_TOKEN(Strings, 2, '|') AS Domain INTO ComputerToValidate.csv FROM 'Security.evtx' WHERE EventID = 4776 AND Domain NOT IN ('NT AUTHORITY') AND Username NOT LIKE '%$'" -o:CSV
Write-Host  " "

#Write-Host  "event id 4778" -ForegroundColor green  
Write-Host  "RDP session reconnected" -ForegroundColor green
Write-Host  "Creating file ---> RDPReconnected.csv"  -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date,EXTRACT_TOKEN(Strings, 0, '|') AS Username, EXTRACT_TOKEN(Strings, 1, '|') AS Domain, EXTRACT_TOKEN(Strings, 4, '|') AS Workstation, EXTRACT_TOKEN(Strings, 5, '|') AS SourceIP  INTO RDPReconnected.csv FROM 'Security.evtx' WHERE EventID = 4778" -o:CSV
Write-Host  " "

#Write-Host  "event id 4779" -ForegroundColor green 
Write-Host  "RDP session disconnected" -ForegroundColor green
Write-Host  "Creating file ---> RDPDisconnected.csv" -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date,EXTRACT_TOKEN(Strings, 0, '|') AS Username, EXTRACT_TOKEN(Strings, 1, '|') AS Domain, EXTRACT_TOKEN(Strings, 4, '|') AS Workstation, EXTRACT_TOKEN(Strings, 5, '|') AS SourceIP  INTO RDPDisconnected.csv FROM 'Security.evtx' WHERE EventID = 4779" -o:CSV
Write-Host  " "
#Write-Host  "event id 4781" -ForegroundColor green 
Write-Host  "User account was renamed" -ForegroundColor green 
Write-Host  "Creating file ---> AccountRenamed.csv" -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 0, '|') AS newname, EXTRACT_TOKEN(Strings, 1, '|') AS oldname, EXTRACT_TOKEN(Strings, 2, '|') AS accdomain, EXTRACT_TOKEN(Strings, 5, '|') AS Username, EXTRACT_TOKEN(Strings, 6, '|') AS Domain INTO AccountRenamed.csv FROM 'Security.evtx' WHERE EventID = 4781" -o:CSV
Write-Host  " "
#Write-Host  "event id 4825" -ForegroundColor green 
Write-Host  "RDP Access denied" -ForegroundColor green
Write-Host  "Creating file ---> RDPAccessDenied.csv" -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 0, '|') AS Username, EXTRACT_TOKEN(Strings, 1, '|') AS Domain, EXTRACT_TOKEN(Strings, 3, '|') AS SourceIP INTO RDPAccessDenied.csv FROM 'Security.evtx' WHERE EventID = 4825" -o:CSV
Write-Host  " "

#Write-Host  "event id 4946" -ForegroundColor green 
Write-Host  "new exception was added to firewall" -ForegroundColor green 
Write-Host  "Creating file ---> FirewallException.csv" -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT  "Select TimeGenerated AS Date, extract_token(strings, 2, '|') as rulename INTO FirewallException.csv FROM 'Security.evtx' WHERE EventID = 4946" -o:CSV
Write-Host  " "

#Write-Host  "event id 4948" -ForegroundColor green 
Write-Host  "rule was deleted from firewall " -ForegroundColor green 
Write-Host  "Creating file ---> FirewallRuleDeleted.csv" -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT   "Select TimeGenerated AS Date, extract_token(strings, 2, '|') as rulename INTO FirewallRuleDeleted.csv FROM 'Security.evtx' WHERE EventID = 4948" -o:CSV
Write-Host  " "

#Write-Host  "event id 5038" -ForegroundColor green 
Write-Host  "Code integrity determined that the image hash of a file is not valid" -ForegroundColor green 
Write-Host  "Creating file ---> HASHFileNoValid.csv" -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT   "SELECT * INTO HASHFileNoValid.csv FROM 'Security.evtx' WHERE EventID = '5038'" -o:CSV
Write-Host  " "

#Write-Host  "event id 5140" -ForegroundColor green 
Write-Host  "A network share object was accessed" -ForegroundColor green 
Write-Host  "Creating file ---> NetworkShareAccessed.csv" -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT   "SELECT * INTO NetworkShareAccessed.csv FROM 'Security.evtx' WHERE EventID = '5140'" -o:CSV
Write-Host  " "
#Write-Host  "event id 5142" -ForegroundColor green 
Write-Host  "A network share object was added" -ForegroundColor green
Write-Host  "Creating file ---> NetworkShareAdd.csv" -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT   "SELECT * INTO NetworkShareAdd.csv FROM 'Security.evtx' WHERE EventID = '5142'" -o:CSV
Write-Host  " "

#Write-Host  "event id 5154"  -ForegroundColor green
Write-Host  "The Windows Filtering Platform has permitted an application or service to listen on a port for incoming connections" -ForegroundColor green 
Write-Host  "Creating file ---> FirewallPermittedIncomingConnections.csv" -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT   "SELECT * INTO FirewallPermittedIncomingConnections.csv FROM 'Security.evtx' WHERE EventID = '5154'" -o:CSV
Write-Host  " "
#Write-Host  "event id 5155" -ForegroundColor green 
Write-Host  "The Windows Filtering Platform has blocked an application or service from listening on a port for incoming connections" -ForegroundColor green
Write-Host  "Creating file ---> FirewallBlockedIncomingConnections.csv" -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT   "SELECT * INTO FirewallBlockedIncomingConnections.csv FROM 'Security.evtx' WHERE EventID = '5155'" -o:CSV
Write-Host  " "
#Write-Host  "event id 5156" -ForegroundColor green 
Write-Host  "The Windows Filtering Platform has allowed a connection" -ForegroundColor green 
Write-Host  "Creating file ---> FirewallAllovedConnections.csv" -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT   "SELECT * INTO FirewallAllovedConnections.csv FROM 'Security.evtx' WHERE EventID = '5156'" -o:CSV
Write-Host  " "
#Write-Host  "event id 5157"  -ForegroundColor green
Write-Host  "The Windows Filtering Platform has blocked a connection" -ForegroundColor green 
Write-Host  "Creating file ---> FirewallBlockedConnections.csv" -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT   "SELECT * INTO FirewallBlockedConnections.csv FROM 'Security.evtx' WHERE EventID = '5157'" -o:CSV
Write-Host  " "
#Write-Host  "event id 5158" -ForegroundColor green 
Write-Host  "The Windows Filtering Platform has permitted a bind to a local port" -ForegroundColor green 
Write-Host  "Creating file ---> FirewallBindLocalPort.csv" -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT   "SELECT * INTO FirewallBindLocalPort.csv FROM 'Security.evtx' WHERE EventID = '5158'" -o:CSV
Write-Host  " "
#Write-Host  " event id 5159" -ForegroundColor green
Write-Host  "The Windows Filtering Platform has blocked a bind to a local port" -ForegroundColor green 
Write-Host  "Creating file ---> FirewallBlockedBindLocalPort.csv" -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT   "SELECT * INTO FirewallBlockedBindLocalPort.csv FROM 'Security.evtx' WHERE EventID = '5159'" -o:CSV
Write-Host  " "
Write-Host  "**********************************************"  -ForegroundColor red -BackgroundColor white
Write-Host  "                  System Log                 *"  -ForegroundColor red -BackgroundColor white 
Write-Host  "**********************************************"  -ForegroundColor red -BackgroundColor white
Write-Host  " "
#Write-Host  "EventID 7045"   -ForegroundColor green
Write-Host  "New Service was installed in system"  -ForegroundColor green
Write-Host  "Creating file ---> NewServiceInstalled.csv" -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT   "Select TimeGenerated AS Date, extract_token(strings, 0, '|') AS ServiceName, extract_token(strings, 1, '|') AS ServicePath, extract_token(strings, 4, '|') AS ServiceUser INTO NewServiceInstalled.csv FROM System.evtx WHERE EventID = 7045" -o:CSV
Write-Host  " "
#Write-Host  "EventID 7036"  -ForegroundColor green
Write-Host  " "
Write-Host  "**********************************************"  -ForegroundColor red -BackgroundColor white
Write-Host  "             Task Scheduler Log              *"  -ForegroundColor red -BackgroundColor white 
Write-Host  "**********************************************"  -ForegroundColor red -BackgroundColor white
Write-Host  " " 
#Write-Host  "EventID 100 "  -ForegroundColor green
Write-Host  "Task was run"  -ForegroundColor green
Write-Host  "Creating file ---> TasksRun.csv" -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT   "Select TimeGenerated AS Date, extract_token(strings,0, '|') as taskname, extract_token(strings, 1, '|') as username INTO TasksRun.csv FROM 'Microsoft-Windows-TaskScheduler%4Operational.evtx' WHERE EventID = 100" -o:CSV
Write-Host  " "

#Write-Host  "eventid 200"  -ForegroundColor green
Write-Host  " action was executed" -ForegroundColor green 
Write-Host  "Creating file ---> ActionsExecuted.csv" -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT   "Select TimeGenerated AS Date, extract_token(strings,0, '|') as taskname, extract_token(strings, 1, '|') as taskaction INTO ActionsExecuted.csv FROM 'Microsoft-Windows-TaskScheduler%4Operational.evtx' WHERE EventID = 200" -o:CSV
Write-Host  " "

#Write-Host  "eventid 140" -ForegroundColor green 
Write-Host  "user updated a task" -ForegroundColor green 
Write-Host  "Creating file ---> UpdatedTask.csv" -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT   "Select TimeGenerated as Date, extract_token(strings, 0, '|') as taskname, extract_token(strings, 1, '|') as user INTO UpdatedTask.csv FROM 'Microsoft-Windows-TaskScheduler%4Operational.evtx' WHERE EventID = 140" -o:CSV
Write-Host  " "

#Write-Host  "event id 141"  -ForegroundColor green 
Write-Host  "user deleted a task" -ForegroundColor green 
Write-Host  "Creating file ---> UserDeletedTask.csv" -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT   "Select TimeGenerated as Date, extract_token(strings, 0, '|') as taskname, extract_token(strings, 1, '|') as user INTO UserDeletedTask.csv FROM 'Microsoft-Windows-TaskScheduler%4Operational.evtx' WHERE EventID = 141" -o:CSV
Write-Host  " "
Write-Host  "**********************************************"  -ForegroundColor red -BackgroundColor white
Write-Host  "           RDP LocalSession Log              *"  -ForegroundColor red -BackgroundColor white 
Write-Host  "               Local logins                  *"  -ForegroundColor red -BackgroundColor white               
Write-Host  "**********************************************"  -ForegroundColor red -BackgroundColor white
Write-Host  " "
#Write-Host  "Event id 21" -ForegroundColor green 
Write-Host  "Successful logon"  -ForegroundColor green
Write-Host  "Creating file ---> RDPLocalSuccessfulLogon.csv" -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT   "Select timegenerated as Date, extract_token(strings, 0, '|') as user, extract_token(strings, 2, '|') as sourceip INTO RDPLocalSuccessfulLogon.csv FROM 'Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx' WHERE EventID = 21" -o:CSV
Write-Host  " "
Write-Host  "**********************************************"  -ForegroundColor red -BackgroundColor white
Write-Host  "           RDP RemoteSession Log             *"  -ForegroundColor red -BackgroundColor white 
Write-Host  "               Remote logins                 *"  -ForegroundColor red -BackgroundColor white               
Write-Host  "**********************************************"  -ForegroundColor red -BackgroundColor white
Write-Host  " "
#Write-Host  "Event ID 1149"  -ForegroundColor green
Write-Host  "Successful logon"  -ForegroundColor green
Write-Host  "Creating file ---> RDPRemoteSuccessfulLogon.csv" -ForegroundColor green
.\LogParser.exe -stats:OFF -i:EVT   "Select timegenerated as Date, extract_token(strings, 0, '|') as user, extract_token(strings, 2, '|') as sourceip INTO RDPRemoteSuccessfulLogon.csv FROM 'Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx' WHERE EventID = 1149" -o:CSV
Write-Host  " "
Write-Host  "--------------------------------------------------------------------- "
Write-Host  "                       END PARSERATOR                                 "
Write-Host  "--------------------------------------------------------------------- "
Write-Host  " "
