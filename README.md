# Parserator
# Windows EVTX Analysis

Everything related to the automatic processing of EVTX files

Parserator.ps1 - Scans the EVTX 

Returns them in CSV format for further processing in Elastic or Excel

At the moment you need to have the following EVTX on the "ps1" route:

* Microsoft-Windwos-TaskScheduler% 4Operational.evtx

* Microsoft-Windows-TerminalServices-LocalSessionManager% 4Operational.evtx

* Microsoft-Windows-TerminalServices-RemoteConnectionManager% 4Admin.evtx

* Microsoft-Windows-TerminalServices-RemoteConnectionManager% 4Operational.evtx

* Security.evtx

* System.evtx

Once you get them run ".\Parserator.ps1" and be happy
