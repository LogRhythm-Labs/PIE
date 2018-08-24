
    PIE Outlook Button
    LogRhythm Labs
    zack . rowland @ logrhythm . com
    v2.0  --  August, 2018

Copyright 2018 LogRhythm Inc.   
Licensed under the MIT License. See LICENSE file in the project root for full license information.


### About

The PIE button can be obtained from the [PIE Button GitHub Repo](https://github.com/LogRhythm-Labs/PIE-Button). This requires manual compilation and installation.

In addition to the PIE button, there are many other (free) options available that you may wish to consider. The main requirement is that the email is delivered to the PIE server as an attachment, so even simply instructing your user base is a great first step towards making PIE a success within your environment.

[Open Source Phishing Button by Elucidant](https://github.com/elucidant/phishingoutlookaddin)

[Microsoft - Macro Forwarding Button (INSECURE)](https://msdn.microsoft.com/en-us/library/office/ee814736(v=office.14).aspx)

	Office Macro Example - from https://stackoverflow.com/questions/28840066/forward-email-with-its-attachment-in-outlook-2010:
		Sub ForwardEmail(item As Outlook.MailItem)
		  Dim oMail As MailItem

		  On Error GoTo Release

		  If item.Class = olMail Then
		     Set oMail = item.Forward
		     oMail.Subject = oMail.Subject
		     oMail.HTMLBody = "Thank you for reporting this phishing email." & vbCrLf & oMail.HTMLBody
		     oMail.Recipients.Add "PHISHING@EMAIL.REPORT"

		     oMail.Save
		     oMail.Send
		  End If
		 Release:
		  Set oMail = Nothing
		  Set oExplorer = Nothing
		End Sub

[Microsoft - Creating a Junk Mail Reporting Button](https://technet.microsoft.com/en-us/library/jj723139(v=exchg.150).aspx)

[KnowBe4 Phish Alert](https://www.knowbe4.com/free-phish-alert) 

#### Please keep in mind that these other options may need some customizations to get these integrations to work properly with PIE.


## [License]

Copyright 2018 LogRhythm Inc.   
Licensed under the MIT License. See LICENSE file in the project root for full license information.
