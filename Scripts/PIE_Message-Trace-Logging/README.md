
    Phishing Intelligence Engine
    LogRhythm Security Operations
    greg . foss @ logrhythm . com
    v1.0  --  November, 2017

Copyright 2017 LogRhythm Inc.   
Licensed under the MIT License. See LICENSE file in the project root for full license information.


## [About]
    
#### Invoke-O365Trace.ps1 is the core of the Phishing Intelligence Engine.

This script handles the message trace logging, dynamic analytics, and automated triage + response to phishing attacks. Additionally, this script collects Office 365 Log data via the EWS API, so that it can be aggregated in the SIEM.

##### If you're looking to deploy only message trace logging - use [Basic Message Trace Logging](/Scripts/Basic_Message-Trace-Logging/).

## [Install]

	1) Build a Windows Server and install Microsoft Outlook. Configure Outlook with access to your defined Phishing Inbox.

    2) Set up auto-response for all new messages on the Phishing inbox, and notify your users to forward suspected phishing messages here. Leave Outlook open on the server.

    3) Copy the entire contents of this folder over to the directory you plan to run PIE from on the Windows server.

    4) Open the Invoke-O365Trace.ps1 script and review the contents. You will need to add credentials and API keys where desired.

        Review lines 40 through 67
            
            Add credentials under each specified section - Office 365 Connectivity and LogRhythm Case API Integration
            Define the folder where you will deploy the Invoke-O365MessageTrace.ps1 script from

        Review Lines 70 through 124
            
            For each setting that you would like to enable, change the value from $false to $true
            For each enabled third party plugin, set the API key and other required paramters

    5) Open the plugins directory. Within this folder, edit Case-API.ps1

        Review Line 30

            Edit the $caseFolder parameter to define where you installed PIE, per step 4. Ensure that you leave \plugins at the end.

    6) Run Invoke-O365Trace.ps1 manually (no switches required) and ensure that logs are being pulled into the 'logs' directory.

        Don't worry about the warnings that are thrown - this is completely normal.

    7) Configure Invoke-O365Trace.ps1 to run as a scheduled task every 5 minutes.
        
        C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -command "& 'C:\PIE_INSTALL_DIR\Invoke-O365Trace.ps1'"

    8) Configure the LogRhythm SIEM to ingest this data, import the installed dashboards, and configure desired AIE alarms.

        Office 365 Message Tracking parsing - Should be included in the Knowledge Base, but if it is not, you can use the following RegEx:
            
            ^"(?<session>[^"]*)","[^"]*","(?<sender>[^"]*)","(?<recipient>[^"]*)",(?:"<dip>")?,(?:"<sip>")?,(?:"(?<subject>.*?)")?,"(?<command>(?<status>[^"]*))","(?<size>\d*)"


## [API Integrations]

[Cisco AMP ThreatGRID](https://panacea.threatgrid.com/login)

[Domain Tools](https://domaintools.com)

[Get Link Info](http://getlinkinfo.com/)

[OpenDNS](https://www.opendns.com/)

[Phish Tank](http://www.phishtank.com)

[Sucuri](https://sucuri.net/)

[Screenshot Machine](http://screenshotmachine.com/)

[Swift On Security RegEx](https://github.com/SwiftOnSecurity/PhishingRegex)

[URL Void](http://api.urlvoid.com/)

[VirusTotal](https://virustotal.com)

[Wrike](https://www.wrike.com/)

And more coming soon...


## [Usage]

The /logs/ directory will populate every time the Invoke-script is run. By default, this is configured to run evey 5-minutes.

If you configure the script to handle phishing attacks, you will be presented with a 'cases' folder. Each phishing attack will be given a folder, and associated evidence will be stored within If you enable LogRhythm Case integration, new cases will be created within the SIEM, allowing for collaboration, tracking, and automated metrics.

![Case Management](/images/Case-Management.png)

Automated response actions can be configured based on a weighting system. Every positive indicator from the email analysis increments the overall threat score. So, if this is set to 5, and the site is detected as malicious in Phish Tank, and VirusTotal flags on 7 engines then the overall threat score will be 8, and auto-quarantine will initiate.

![Auto Quarantine](/images/Case-Quarantine.png)

All third party plugins are contained within the 'plugins directory' and any of the smaller functions are included directly in Invoke-O365Trace.ps1. There is no need to modify anything within this directory, unless adding integrations.

To maximize value from this script, couple this with Invoke-O365Ninja.ps1 for automated response to Phishing attacks.

Stay on top of the messages that are coming in, and develop custom AIE rules within the SIEM to detect and respond to these attacks.


## [License]

Copyright 2017 LogRhythm Inc.   
Licensed under the MIT License. See LICENSE file in the project root for full license information.
