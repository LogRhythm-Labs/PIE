
    Phishing Intelligence Engine
    LogRhythm Security Operations
    greg . foss @ logrhythm . com
    v1.0  --  November, 2017

Copyright 2017 LogRhythm Inc.   

This content is licensed pursuant to the [LogRhythm End User License Agreement](https://logrhythm.com/about/logrhythm-terms-and-conditions/)


## [About]
    
These SmartResponse scripts are the automation arm of PIE. These are meant to be integrated with the SIEM and tied to alarms, allowing for workflow automation around message quarantine, sender blocking, and ongoing spammer tracking.


## [Install and Usage]

#### 1) O365-Ninja.lpi

This SmartResponse is the SIEM integration of the [O365-Ninja.ps1](/Scripts/O365-Ninja/README.md) script, allowing for automation directly within the SIEM.

![O365-Ninja SmartResponse](/images/O365-Ninja-SmartResponse.png)

#### 2) Spam-Tracker.lpi

This SmartResponse adds all known spammers to a list, for ongoing tracking and automation.

![SPAM Tracker](/images/Spam-Tracker.png)

You can also take advantage of the existing SmartResponse - AddItemToList.lpi, which can be found on the [LogRhythm Community Portal](https://community.logrhythm.com)

## [License]

Copyright 2017 LogRhythm Inc.   

This content is licensed pursuant to the LogRhythm End User License Agreement located at https://logrhythm.com/about/logrhythm-terms-and-conditions/ (“License Agreement”) and by downloading and using this content you agree to the terms and conditions of the License Agreement unless you have a separate signed end user license agreement with LogRhythm in which case that signed agreement shall govern your licensed use of this content. For purposes of the applicable end user license agreement, this content constitutes LogRhythm Software