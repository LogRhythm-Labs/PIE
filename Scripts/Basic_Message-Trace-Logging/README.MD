
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

2) Decide how you would like to store credentials - both options have a level of risk, so ensure you monitor the PIE server appropriately!

    a) Generate an XML document containing the credentials for the inbox and service account.

        Set $EncodedXMLCredentials = $true

        Run the following commands, and take note of the filenames and where these files are stored:

        PS C:\> Get-Credential | Export-Clixml Service-Account_cred.xml

        Enter the full path to the XML file on line 57

    b) Enter plain text passwords.

        Set $PlainText = $true

        Enter your service account credentials on lines 62 and 63

3) Set $logFolder value to the location where the Basic-O365Trace.ps1 script will run from.

4) Configure Invoke-O365Trace.ps1 to run as a scheduled task every 5 minutes.
    
    C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -command "& 'C:\MESASAGE_TRACE_FOLDER\Basic-O365Trace.ps1'"

    When running this script manually, don't worry about the warnings that are thrown - this is completely normal.

5) Configure the LogRhythm SIEM to ingest this data.

    Office 365 Message Tracking parsing - This is included in the LogRhythm Knowledgebase.

    Configure this log source and select 'BETA : LogRhythm  Default' for the Message Processing Engine (MPE) Policy

    ![Log Source Type](/images/O365-Message-Tracking_Log-Source.png)

    Next, set the time parsing under the 'Flat File Settings' tab. If this option does not exist, add the following regex:

        <M>/<d>/<yy> <h>:<m>:<s> <t>

    ![Flat File Settings](/images/O365-Message-Tracking_Time-Format.png)
    
    If you'd like to customize the parsing in any way, below is the current RegEx used to parse Office 365 Message Tracking logs:

        ^"(?<session>[^"]*)","[^"]*","(?<sender>[^"]*)","(?<recipient>[^"]*)",(?:"<dip>")?,(?:"<sip>")?,(?:"(?<subject>.*?)")?,"(?<command>(?<status>[^"]*))","(?<size>\d*)"

6) Import the PIE dashboards, and configure desired AIE alarms.

## [License]

Copyright 2017 LogRhythm Inc.   
Licensed under the MIT License. See LICENSE file in the project root for full license information.
