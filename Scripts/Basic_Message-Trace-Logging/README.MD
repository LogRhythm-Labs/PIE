
    Message Tracking - BASIC
    LogRhythm Security Operations
    greg . foss @ logrhythm . com
    v1.0  --  November, 2017

Copyright 2017 LogRhythm Inc.   
Licensed under the MIT License. See LICENSE file in the project root for full license information.


## [About]
    
Basic-O365Trace.ps1 is a simple message tracking log aggregation script. This will connect to Office 365 and extract Office 365 Message Tracking Logs in the 'logs' folder and rotate them every 50MB.

##### This does not include Phishing Automation and analytics. For the full Phishing Intelligence Engine, visit [PIE Message Trace Logging](/Scripts/PIE_Message-Trace-Logging/).


## [Usage]

	1) Run Invoke-O365Trace.ps1 manually (no switches required) and ensure that logs are being pulled into the 'logs' directory.

        Don't worry about the warnings that are thrown - this is completely normal.

    2) Configure Invoke-O365Trace.ps1 to run as a scheduled task every 5 minutes.
        
        C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -command "& 'C:\MESASAGE_TRACE_FOLDER\Basic-O365Trace.ps1'"

        When running this script manually, don't worry about the warnings that are thrown - this is completely normal.

    3) Configure the LogRhythm SIEM to ingest this data, and import the installed dashboards, and configure desired AIE alarms.

        Office 365 Message Tracking parsing - Should be included in the Knowledge Base, but if it is not, you can use the following RegEx:
            
            ^"(?<session>[^"]*)","[^"]*","(?<sender>[^"]*)","(?<recipient>[^"]*)",(?:"<dip>")?,(?:"<sip>")?,(?:"(?<subject>.*?)")?,"(?<command>(?<status>[^"]*))","(?<size>\d*)"


## [License]

Copyright 2017 LogRhythm Inc.   
Licensed under the MIT License. See LICENSE file in the project root for full license information.
