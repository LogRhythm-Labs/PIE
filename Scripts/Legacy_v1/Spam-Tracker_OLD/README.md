
    Spam Tracker
    LogRhythm Security Operations
    greg . foss @ logrhythm . com
    v1.0  --  November, 2017

Copyright 2017 LogRhythm Inc.   
Licensed under the MIT License. See LICENSE file in the project root for full license information.


## [About]
    
Simple script to append spammer email addresses to a remote threat list.


## [Usage]

Configure as a SmartResponse or run the script directly to add spammers to a remote server's threat list
    
	powershell.exe Spam-Tracker.ps1 -email "<address"> -LogRhythmHost <ip> -spammerList "\\\someshare\somefile.txt" -caseAPItoken <api key>


## [License]

Copyright 2017 LogRhythm Inc.   
Licensed under the MIT License. See LICENSE file in the project root for full license information.
