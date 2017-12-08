
    Alarm Configuration and Threat Lists
    LogRhythm Security Operations
    v1.1  --  December, 2017

Copyright 2017 LogRhythm Inc.   
Licensed under the MIT License. See LICENSE file in the project root for full license information.


## [About]
    
There are many options available when it comes to leveraging this log source for active defense within your network. Below are some example rules that you can build and tune within your environment, to detect and alert on email attacks. The real meat of this configuration comes from the adaptive use of lists, both within the SIEM, and within the PIE scripts directly.

The threat lists included within this repository are an adaption of the ones developed by [@SwiftOnSecurity](https://twitter.com/SwiftOnSecurity) and openly available here: [https://github.com/SwiftOnSecurity/PhishingRegex/blob/master/PhishingRegex.txt](https://github.com/SwiftOnSecurity/PhishingRegex/blob/master/PhishingRegex.txt). I'd recommend taking a look at their page on [responding to Phishing attacks](https://decentsecurity.com/#/malware-web-and-phishing-investigation/) as well, lots of great information here. You should test these rules, add new ones, and otherwise adapt them with a whitelist of known-good senders to optimize the integration of these lists with AIE alarms.

Once you have AIE alarms configured, you may choose to implement [SmartResponse's](/SmartResponse/) to automate the response to threats as they come through within the SIEM. If you go down this path, it is recommended that you implement an approval process, to ensure the inadvertent quarantine and blocking of mail from legitimate senders.


## [Configuration]

1) Phishing Message Reported AIE Rule: This rule fires an alarm whenever a Phishing email is reported, allowing you to associate this with the case that will be automatically generated whenever a Phishing email is reported. Configure this rule to fire whenever an email is sent to your phishing inbox.

![Phishing Message Reported AIE](/images/AIE_Phishing-Email-Reported.png)

2) Known Spammers AIE Rule: This rule ties to threat feeds that contain email addresses. There are various commercial and open source threat feeds that you can utilize to take advantage of this rule. Our suggestion is to start tracking all phishing attacks, and build this list out internally using the [Spam-Tracker SmartResponse](/Scripts/Spam-Tracker/) and spammers will be automatically added to your threat list whenever a phishing attack is detected.

![Known Spammers AIE](/images/AIE_Known-Spammers.png)

3) Suspicious Subject AIE Rule: This rule fires whenever a subject string matches the included LR-Threat-List_Email Subject_Phishing.txt list items. Before tying SmartResponses to this alarm, you'll want to tune the list, to add/remove items that will cause false positives. Most importantly, be sure to whitelist known-good senders, to avoid false positives going forward.

![Suspicious Subject AIE](/images/AIE_Suspicious-Subject.png)

4) MailSploit AIE Rule: This rule will fire whenever a known mailsploit attack is detected. Currently, LogRhythm can identify 7 of the 14 attacks described at https://mailsploit.com using a basic RegEx check. For the other 7 attacks, the actual sender is parsed out of the email, so even though the message is spoofed, analysts can easily locate the true sender, quarantine mail from them, and block future attacks. It is possible to detect all MailSploit variants, however to do this, you need access to the email headers. This is something I plan to add to the PIE code directly in the near future.

![MailSploit AIE](/images/AIE_MailSploit.png)

5) LogRhythm Threat Intelligence Service (TIS): There are many other ways to utilize these logs, and alarms. Take advantage of the many open source and commercially available threat feeds, and generate your own, to begin to take control of phishing attacks within your company. TIS can be found on the LogRhythm Community Poratl.

![Threat Feeds](/images/Commercial-and-OpenSource-Threat-Feeds.png)


## [License]

Copyright 2017 LogRhythm Inc.   
Licensed under the MIT License. See LICENSE file in the project root for full license information.
