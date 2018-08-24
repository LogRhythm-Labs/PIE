
    Phishing Intelligence Engine
    LogRhythm Security Operations
    greg . foss @ logrhythm . com
    v2.0  --  August, 2018

Copyright 2018 LogRhythm Inc.   

This content is licensed pursuant to the [LogRhythm End User License Agreement](https://logrhythm.com/about/logrhythm-terms-and-conditions/)


## [About]
    
These SmartResponse scripts are the automation arm of PIE. These are meant to be integrated with the LogRhythm SIEM and tied to alarms, allowing for workflow automation around message quarantine, sender blocking, and ongoing spammer tracking. This SmartResponse works with LogRhythm version 7.3


## [Install and Usage]

#### O365-Ninja.lpi

This SmartResponse is the SIEM integration of the [O365-Ninja.ps1](/Scripts/O365-Ninja/README.md) script, allowing for automation directly within the SIEM. Actions available are extracting mail, quarantining mail, blocking/unblocking senders, and appending spammers to threat lists.

![O365-Ninja SmartResponse](/images/O365-Ninja-SmartResponse.png)

Ensure that the user running this script is a member of the "Discovery Management Exchange Security Group" and that "Search and Destroy" permissions are enabled.
    
    More information: https://technet.microsoft.com/en-us/library/dd298059(v=exchg.160).aspx

![Mailbox Import Export](/images/Mailbox-Import-Export.png)


## [License]

Copyright 2018 LogRhythm Inc.   

This content is licensed pursuant to the LogRhythm End User License Agreement located at https://logrhythm.com/about/logrhythm-terms-and-conditions/ (“License Agreement”) and by downloading and using this content you agree to the terms and conditions of the License Agreement unless you have a separate signed end user license agreement with LogRhythm in which case that signed agreement shall govern your licensed use of this content. For purposes of the applicable end user license agreement, this content constitutes LogRhythm Software