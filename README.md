<img align="center" src="/images/PIE-Logo.png" width="125px" alt="PIE">

    Phishing Intelligence Engine
    LogRhythm Security Operations
    v3.0  --  April, 2019

Copyright 2019 LogRhythm Inc. - See licensing details below

## [About]
    
![Phishing Intelligence Engine](/images/PIE.png)

The Phishing Intelligence Engine (PIE) is a framework that will assist with the detection and response to phishing attacks. An Active Defense framework built around Office 365, that continuously evaluates Message Trace logs for malicious contents, and dynamically responds as threats are identified or emails are reported.

##### :rotating_light: This framework is not officially supported by LogRhythm - use at your own risk! :rotating_light:

#### Features:

    - Analyze subjects, senders, and recipients using RegEx and Threat Feed correlation, to determine email risk.
    - Automatically respond to attacks by quarantining mail, blocking senders, and checking for clicks.
    - Sandbox analytics on all flagged email attachments and links.
    - Dynamic Case Management integration and metrics tracking.
    - Prevent sensitive data loss and verify corporate email security.

#### 3.0 Updates:

	- 365 Message Trace: Removed 5 minute runtime requirement.  Invoke-O365Trace.ps1 can be executed at any interval. 
	- 365 Message Trace: Added support for .eml format e-mail submissions.
	- 365 Message Trace: PIE execution log available under PIE/logs/pierun.txt.
	- 365 Message Trace: Increased message processing threshold from 1,000 to 1,000,000 messages per execution.
	- 365 Message Trace: Added handler for special characters in e-mail subject line.
	- 365 Message Trace: Updated autoAuditMailboxes to support handling multiple matched entries.
	- 365 Message Trace: Added support to filter out user@example.onmicrosoft.com from message counts.
	- 365 Message Trace: Added URL whitelist to prevent scanning/analysis of frequenty legitimate sources.
	- 365 Message Trace: New E-mail Address Template Config.
	- 365 Message Trace: Parsing of Office 365 Safe Links is now automatic and does not require configuration.
	- 365 Message Trace: Various Bug Fixes and execution improvements.
	- LogRhythm Case: Added e-mail message text body to case notes.
	- LogRhythm Case: Added e-mail links to case notes.
	- LogRhythm Case: Added subjects to case notes.
	- LogRhythm Dashboard: Added PIE Case Management dashboard template.
	- Shodan Plugin: Now enumerates all services identified on host by Shodan.
	- Shodan Plugin: Added handler for IP addresses that have not ben scanned by Shodan.
	- Urlscan Plugin: New plugin.  Initiates URL scan for each URL and provides links to URLScan report and screenshot of the URL.
	- Urlscan Plugin: Optional parameter to download screenshots locally to case folder.
	- Urlscan/VirusTotal: If a link is direct to a file, the file's hash is submitted forward to VirusTotal and recorded.
	- Urlscan/Wildfire: If a link is direct to a file, the file's hash is submitted forward to Wildfire and recorded.
	- Sucuri Plugin: Updated to support Sucuri API v3.  Presents more in-depth information to the Case Report and LogRhythm Case.
	- VirusTotal: Updated URL and File hash submission handlers.
	- VirusTotal: Presents more in-depth information to the Case Report and LogRhythm Case.
	- VirusTotal: Added support for Public API with submission rate limiting.  Commercial API use with no rate limit.
	- SmartResponse: New SmartResponse 365-Security and Compliance Controller.  Supports the following actions: Compliance Search, Purge, Compliance Search & Purge.


## [Additional Information]

Blog Post: https://logrhythm.com/blog/phishing-intelligence-engine-open-source-release/

BSides Vancouver 2018 Slides and Video: https://www.slideshare.net/heinzarelli/pie-bsides-vancouver-2018

BlueHat v17 Slides: https://www.slideshare.net/heinzarelli/phishing-intelligence-engine-bluehat-v17

Black Hat 2017 Slides: https://www.slideshare.net/heinzarelli/security-automation-and-orchestration

Security Weekly Webcast: https://www.youtube.com/watch?v=2oGMoGr4qBI 


## [Install and Usage]

Installation Walkthrough: https://www.youtube.com/watch?v=19bHJL0g154&feature=youtu.be

Configuration Guide (LogRhythm Community Access Required): https://community.logrhythm.com/t5/SIEM-articles/Phishing-Intelligence-Engine-PIE-Configuration-Guide/ta-p/39931

There are multiple aspects of this framework that all work together to detect and respond to Phishing attacks:

#### 1) [PIE Message Trace Logging](/Scripts/PIE_Message-Trace-Logging/)

The core of the Phishing Intelligence Engine - provides ongoing logging via the API, third party tool integrations, and automated email response.

#### 2) [Office 365 Ninja](/Scripts/O365-Ninja/)

The response arm of PIE. Quarantine mail, block senders, change credentials, check Office 365 configurations, and more.

#### 3) [SPAM Tracker](/Scripts/Spam-Tracker/)

List updater for ongoing tracking of spammer email addresses.

#### 4) [LogRhythm SIEM Dashboards](/SIEM-Dashboards/)

Analyst and Investigation Dashboards, which allow for searching and aggregation of Office 365 Data within the LogRhythm SIEM.

#### 5) [Alarms and Threat Lists](Alarms_and_Threat-Lists)

LogRhythm AIE alarm configurations and Threat List integrations.

#### 6) [LogRhythm SmartResponse](/SmartResponse/)
    
Plugins that can be integrated with the LogRhythm SIEM, allowing for automated response to alarms.

#### 7) [Report Phishing Message Button](/Outlook-Button/)

Addon for Microsoft Outlook to allow for easy reporting of Phishing Attacks.

#### 8) [Architecture](/images/PIE-Architecture.png)

High level overview of the PIE architecture and workflow:

![PIE Architecture](/images/PIE-Architecture.png)


## [Thanks!]

This project would not be a success without the folks below and the various third-party API integration providers. Thank you!

- [Jtekt](https://github.com/Jtekt) - PIE 3.0 Base, UrlScan Plugin, Shodan Plugin, O365 Safelinks, bug fixes, and LR 7.3 API integration
- bruce deakyne -  Cisco AMP Threat GRID Plugin
- Gewch, LogRhythm Community - Special character handler in e-mail subject line
- jake reynolds - OpenDNS Plugin
- julian crowley - Message Tracking Log Parsing
- matt willems - LogRhythm Case API Plugin
- shaunessy o'brien - PIE Logo
- sslwater, LogRhythm Community - PIE Message Trace enhancements
- steve warburton - User Acceptance Testing
- zack rowland - Outlook Button
- SwiftOnSecurity - Phishing RegEx


## [Lead Author]

[Greg Foss](https://github.com/gfoss) - formerly of LogRhythm Labs


## [License]

Copyright 2019 LogRhythm Inc.   

PowerShell code is Licensed under the MIT License. See LICENSE file in the project root for full license information.

LogRhythm integrated code (SmartResponse and Dashboards) is licensed pursuant to the LogRhythm End User License Agreement located at https://logrhythm.com/about/logrhythm-terms-and-conditions/ (“License Agreement”) and by downloading and using this content you agree to the terms and conditions of the License Agreement unless you have a separate signed end user license agreement with LogRhythm in which case that signed agreement shall govern your licensed use of this content. For purposes of the applicable end user license agreement, this content constitutes LogRhythm Software
