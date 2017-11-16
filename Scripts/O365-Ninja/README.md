
    Office 365 Ninja
    LogRhythm Security Operations
    greg . foss @ logrhythm . com
    v1.0  --  November, 2017

Copyright 2017 LogRhythm Inc.   
Licensed under the MIT License. See LICENSE file in the project root for full license information.


## [About]
    
Collection of useful commands for easy integration with Office 365 and the LogRhythm SIEM.

Automate the full response to phishing attacks, and take control of your Office 365 security.

![O365-Ninja](/images/O365-Ninja.png)

This script is also integrated directly into the LogRhythm SIEM as a [SmartResponse](/SmartResponse).


## [Install]

Import The Module
	
	PS C:\> Import-Module .\O365-Ninja.ps1


## [Usage]

#### Run the following command for a list of options associated with this script:

    PS C:\> Invoke-O365Ninja -help

#### Command details - all of which can be chained together:

Capture A Specific Email:

	PS C:\> Invoke-O365Ninja -getMail -targetUser "<user.name>" -sender "<spammer>"

Quarantine A Specific Email:

	PS C:\> Invoke-O365Ninja -getMail -targetUser "<user.name>" -sender "<spammer>" -nuke

    Available switches for targeted mail capture:
        -sender, -subject, -recipient

Capture All Emails:

	PS C:\> Invoke-O365Ninja -scrapeMail -sender "<spammer>"

Quarantine All Emails Matching Defined Criteria:

	PS C:\> Invoke-O365Ninja -scrapeMail -sender "<spammer>" -nuke

    Available switches for quarantine / extraction:
        -sender, -subject, -recipient

Block Sender for specific user:

	PS C:\> Invoke-O365Ninja -blockSender -sender "<spammer>" -recipient "<recipient>"

Block Sender for the whole company - WARNING - This may take some time:

	PS C:\> Invoke-O365Ninja -blockSender -sender "<spammer>"

Remove Sender from block list for specific user:

	PS C:\> Invoke-O365Ninja -unblockSender -sender "<not spammer>" -recipient "<recipient>"

Remove Sender from block list for the whole company - WARNING - This may take some time:

	PS C:\> Invoke-O365Ninja -unblockSender -sender "<not spammer>"

Reset End User's Password:

	PS C:\> Invoke-O365Ninja -resetPassword -targetMailbox "User.Name"

Check Auto Forwarding Rules:

	PS C:\> Invoke-O365Ninja -checkForwards

Obtain Group Memberships:

    PS C:\> Invoke-O365Ninja -checkMemberships

************************************************************

All arguments require administrative access to Office 365, and must include the following parameters / supply them at runtime
 
    -username, -password, -socMailbox

To take advantage of the LogRhythm SIEM integrations, the following parameters are required
 
    -LogRhythmHost, -caseAPIToken, -caseNumber (optional - if not supplied a new case will be created)


## [License]

Copyright 2017 LogRhythm Inc.   
Licensed under the MIT License. See LICENSE file in the project root for full license information.
