
  #====================================#
  # PIE - Phishing Intelligence Engine #
  #       Office 365 Ninja             #
  # LogRhythm Security Operations      #
  # greg . foss @ logrhythm . com      #
  # v1.0  --  August, 2017             #
  #====================================#

# Copyright 2017 LogRhythm Inc.   
# Licensed under the MIT License. See LICENSE file in the project root for full license information.

<#

SYNOPSIS:
    
    Collection of useful commands for easy integration with Office 365 and the LogRhythm SIEM.
    Automate the full response to phishing attacks, and dynamically 

USAGE:

    Capture A Specific Email:
    PS C:\> .\O365Ninja-SRP.ps1 -getMail -targetUser "<user.name>" -sender "<spammer>"

    Quarantine A Specific Email:
    PS C:\> .\O365Ninja-SRP.ps1 -getMail -targetUser "<user.name>" -sender "<spammer>" -nuke

        Available switches for targeted mail capture:
            -sender, -subject, -recipient
    
    Capture All Emails:
    PS C:\> .\O365Ninja-SRP.ps1 -scrapeMail -sender "<spammer>"

    Quarantine All Emails Matching Defined Criteria:
    PS C:\> .\O365Ninja-SRP.ps1 -scrapeMail -sender "<spammer>" -nuke

        Available switches for quarantine / extraction:
            -sender, -subject, -recipient
    
    Block Sender for specific user:
    PS C:\> .\O365Ninja-SRP.ps1 -blockSender -sender "<spammer>" -recipient "<recipient>"

    Block Sender for the whole company:
    PS C:\> .\O365Ninja-SRP.ps1 -blockSender -sender "<spammer>"
    
    Reset End User's Password:
    PS C:\> .\O365Ninja-SRP.ps1 -resetPassword -targetMailbox "User.Name"

    ************************************************************

    All arguments require administrative access to Office 365, and must include the following parameters / supply them at runtime
        -username, -password, -socMailbox

    To take advantage of the LogRhythm SIEM integrations, the following parameters are required
        -LogRhythmHost, -caseAPIToken, -caseNumber (optional - if not supplied a new case will be created)

#>

[CmdLetBinding()]
param( 
    [string]$username,
    [string]$password,
    [string]$socMailbox,
    [string]$LogRhythmHost,
    [string]$caseAPItoken,
    [string]$caseNumber,
    [string]$targetUser,
    [string]$sender,
    [string]$recipient,
    [string]$subject,
    [string]$past,
    [switch]$scrapeMail,
    [switch]$getMail,
    [switch]$resetPassword,
    [switch]$blockSender,
    [switch]$nuke = $false
)


$banner = @"
O365 Ninja"@

$usage = @"
USAGE:

    Capture A Specific Email:
    PS C:\> .\O365Ninja-SRP.ps1 -getMail -targetUser "<user.name>" -sender "<spammer>"

    Quarantine A Specific Email:
    PS C:\> .\O365Ninja-SRP.ps1 -getMail -targetUser "<user.name>" -sender "<spammer>" -nuke

        Available switches for targeted mail capture:
            -sender, -subject, -recipient
    
    Capture All Emails:
    PS C:\> .\O365Ninja-SRP.ps1 -scrapeMail -sender "<spammer>"

    Quarantine All Emails Matching Defined Criteria:
    PS C:\> .\O365Ninja-SRP.ps1 -scrapeMail -sender "<spammer>" -nuke

        Available switches for quarantine / extraction:
            -sender, -subject, -recipient
    
    Block Sender for specific user:
    PS C:\> .\O365Ninja-SRP.ps1 -blockSender -sender "<spammer>" -recipient "<recipient>"

    Block Sender for the whole company:
    PS C:\> .\O365Ninja-SRP.ps1 -blockSender -sender "<spammer>"
    
    Reset End User's Password:
    PS C:\> .\O365Ninja-SRP.ps1 -resetPassword -targetMailbox "User.Name"

    ************************************************************

    All arguments require administrative access to Office 365, and must include the following parameters / supply them at runtime
        -username, -password, -socMailbox

    To take advantage of the LogRhythm SIEM integrations, the following parameters are required
        -LogRhythmHost, -caseAPIToken, -caseNumber (optional - if not supplied a new case will be created)
"@


# ================================================================================
# DEFINE GLOBAL PARAMETERS AND CAPTURE CREDENTIALS
# ================================================================================

# Mask errors
$ErrorActionPreference = "silentlycontinue"
$warningPreference = "silentlyContinue"

# date and time
$today = "{0:MM-dd-yyyy}" -f (Get-Date).ToUniversalTime()
$yesterday = "{0:MM-dd-yyyy}" -f ((Get-Date).ToUniversalTime()).AddDays(-1)
$dayBefore = "{0:MM-dd-yyyy}" -f ((Get-Date).ToUniversalTime()).AddDays(-2)

$date = (Get-Date).ToUniversalTime()
$48Hours = ((Get-Date).ToUniversalTime()).AddHours(-48)
$24Hours = ((Get-Date).ToUniversalTime()).AddHours(-24)
$12Hours = ((Get-Date).ToUniversalTime()).AddHours(-12)

# folder structure and global parameters
$companyDomain = $socMailbox.Split("@")[1]
$currentFolder = (Get-Item -Path ".\" -Verbose).FullName
$tmPIEfolder = "$currentFolder\TemporaryPIE\"
mkdir $tmPIEfolder > $null

$traceLog = "$tmPIEfolder\ongoing-trace-log.csv"
$phishLog = "$tmPIEfolder\ongoing-phish-log.csv"
$analysisLog = "$tmPIEfolder\analysis.csv"
$tmpLog = "$tmPIEfolder\srp-tmp.csv"
$tmpFolder = "$tmPIEfolder\tmp\"

Write-Output ""
Write-Output "O365 Ninja"
Write-Output ""

# Assign Credentials and connect to Office365
try {
    if (-Not ($password)) {
        $cred = Get-Credential
    } Else {
        $securePass = ConvertTo-SecureString -string $password -AsPlainText -Force
        $cred = New-Object -typename System.Management.Automation.PSCredential -argumentlist $username, $securePass
    }

    $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $cred -Authentication Basic -AllowRedirection
    Import-PSSession $Session -AllowClobber > $null
} Catch {
    Write-Output "Access Denied..."
    Write-Output ""
    break;
}

# ================================================================================
# TARGETED MAIL CAPTURE AND DELETION
# ================================================================================

if ( $getMail ) {

    if ( $past ) {
        $day = $past
    } else {
        $day = "{0:MM-dd-yyyy}" -f (Get-Date).ToUniversalTime()
    }

    if ( $targetUser ) {
        if ( $subject ) {
            $messageQuery = "Subject:" + '"' + $subject + '"' + " Sent:" + $day
        }
        if ( $sender ) {
            $messageQuery = "from:" + '"' + $sender + '"' + " Sent:" + $day
        }
        if ( $recipient ) {
            $messageQuery = "to:" + '"' + $recipient + '"' + " Sent:" + $day
        }
        if ( $nuke -eq $true ) {
            $searchMailboxResults = Search-Mailbox $targetUser -SearchQuery $messageQuery -TargetMailbox $socMailbox -TargetFolder "PROCESSING" -DeleteContent -Force
        } else {
            $searchMailboxResults = Search-Mailbox $targetUser -SearchQuery $messageQuery -TargetMailbox $socMailbox -TargetFolder "PROCESSING" -LogLevel Full
        }
        $searchMailboxResults
    } else {
        Write-Output "Target User not specified (-targetUser)"
        Write-Output ""
        break;
    }
}


if ( $scrapeMail ) {

    if ( $subject ) {

        for( $c=1; $c -lt 1001; $c++ ) {
            if((Get-MessageTrace -StartDate $12Hours -EndDate $date -PageSize 5000 -Page $c).count -gt 0) {
                Get-MessageTrace -StartDate $12Hours -EndDate $date -PageSize 5000 -Page $c | Select MessageTraceID,Received,*Address,*IP,Subject,Status,Size,MessageID | Export-Csv $tmpLog -NoTypeInformation -Append
            } else {
                break;
            }
        }

        $subjectMatches = type $tmpLog | findstr -i "$subject"
        type $tmpLog | findstr -i "$subject" > $analysisLog
        $spammer = type $analysisLog | ForEach-Object { $_.Split(",")[2]  } | Sort | Get-Unique | findstr "@"
        
        $senderDomain = $spammer.Split("@")[1]

        if ( $senderDomain -eq $companyDomain ) {

            Write-Output "Error - unable to quarantine mail from $sender as they appear to be an internal employee!"
            Write-Output ""
            break;

        } else {
        
            type $analysisLog | ForEach-Object { $_.Split(",")[3]  } | Sort | Get-Unique | findstr "@" > $tmPIEfolder\recipients.txt
            $messageCount = type $analysis | findstr -i $subject | Measure-Object | Select-Object Count | findstr -v "Count -"
            $messageCount = $messageCount.Trim() -match "[0-9+]"
            $messageQuery1 = "Subject:" + '"' + $subject + '"' + " Sent:" + $today
            $messageQuery2 = "Subject:" + '"' + $subject + '"' + " Sent:" + $yesterday
            $messageQuery3 = "Subject:" + '"' + $subject + '"' + " Sent:" + $dayBefore

            $caseQuery = "The subject of the email is ($subject)."
            if ( $messageCount -lt 10 ) {
                $timeframe = "48 hours"
            } else {
                $timeframe = "12 hours"
            }
        }
    }

    if ( $sender ) {
        
        $senderDomain = $sender.Split("@")[1]

        if ( $senderDomain -eq $companyDomain ) {

            Write-Output "Error - unable to quarantine mail from $sender as they appear to be an internal employee!"
            Write-Output ""
            break;

        } else {

            Get-MessageTrace -SenderAddress $sender -StartDate $48Hours -EndDate $date | Select MessageTraceID,Received,*Address,*IP,Subject,Status,Size,MessageID | Export-Csv $tmpLog -NoTypeInformation
            type $tmpLog | findstr -v "MessageTraceId" > $analysisLog
            $messageCount = type $analysisLog | findstr -i $sender | Measure-Object | Select-Object Count | findstr -v "Count -"
            $messageCount = $messageCount.Trim() -match "[0-9+]"
            $spammer = $sender
            type $analysisLog | ForEach-Object { $_.Split(",")[3]  } | Sort | Get-Unique | findstr "@" > $tmPIEfolder\recipients.txt
            $messageQuery1 = "from:" + '"' + $sender + '"' + " Sent:" + $today
            $messageQuery2 = "from:" + '"' + $sender + '"' + " Sent:" + $yesterday
            $messageQuery3 = "from:" + '"' + $sender + '"' + " Sent:" + $dayBefore

            $caseQuery = "The sender of the email is ($sender)."
            if ( $messageCount -lt 10 ) {
                $timeframe = "48 hours"
            } else {
                $timeframe = "12 hours"
            }

        }
    }

    if ( $recipient ) {

        Get-MessageTrace -RecipientAddress $recipient -StartDate $48Hours -EndDate $date | Select MessageTraceID,Received,*Address,*IP,Subject,Status,Size,MessageID | Export-Csv $tmpLog -NoTypeInformation
        type $tmpLog | findstr -v "MessageTraceId" > $analysisLog
        $spammer = type $analysisLog | ForEach-Object { $_.Split(",")[2]  } | Sort | Get-Unique | findstr "@"
        
        $senderDomain = $spammer.Split("@")[1]

        if ( $senderDomain -eq $companyDomain ) {

            Write-Output "Error - unable to quarantine mail from $sender as they appear to be an internal employee!"
            Write-Output ""
            break;

        } else {
        
            type $analysisLog | ForEach-Object { $_.Split(",")[3]  } | Sort | Get-Unique | findstr "@" > $tmPIEfolder\recipients.txt
            $messageCount = type $analysisLog | findstr -i $recipient | Measure-Object | Select-Object Count | findstr -v "Count -"
            $messageCount = $messageCount.Trim() -match "[0-9+]"
            $messageQuery1 = "to:" + '"' + $recipient + '"' + " Sent:" + $today
            $messageQuery2 = "to:" + '"' + $recipient + '"' + " Sent:" + $yesterday
            $messageQuery3 = "to:" + '"' + $recipient + '"' + " Sent:" + $dayBefore

            $caseQuery = "The recipient of the email is ($recipient)."
            if ( $messageCount -lt 10 ) {
                $timeframe = "48 hours"
            } else {
                $timeframe = "12 hours"
            }
        }
    }

    if ( $nuke -eq $true ) {
    
        $getUsers = type $tmPIEfolder\recipients.txt
        
        foreach ($phishRecipient in $getUsers) {
        
            $phishRecipient = $phishRecipient.Split('"')[1]
            $endUserName = $phishRecipient.Split("@")[0]
            $searchMailboxResults1 = Search-Mailbox $endUserName -SearchQuery $messageQuery1 -TargetMailbox $socMailbox -TargetFolder "PROCESSING" -DeleteContent -Force
            if ( $messageCount -lt 10 ) {
                $searchMailboxResults2 = Search-Mailbox $endUserName -SearchQuery $messageQuery2 -TargetMailbox $socMailbox -TargetFolder "PROCESSING" -DeleteContent -Force
                $searchMailboxResults3 = Search-Mailbox $endUserName -SearchQuery $messageQuery3 -TargetMailbox $socMailbox -TargetFolder "PROCESSING" -DeleteContent -Force
            }
        }

        $quarantine = "YES"
        $caseStatus = "Phishing messages have been quarantined and samples have been extracted to the Phishing Case Inbox ($socMailbox) for further analysis..."
        $messageStatus = "Quarantined"
    
        Write-Output "Phishing messages have been quarantined and samples have been extracted to the Phishing Case Inbox for further analysis..."

    } else {

        $getUsers = type $tmPIEfolder\recipients.txt
    
        foreach ($phishRecipient in $getUsers) {
        
            $phishRecipient = $phishRecipient.Split('"')[1]
            $endUserName = $phishRecipient.Split("@")[0]
            $searchMailboxResults1 = Search-Mailbox $endUserName -SearchQuery $messageQuery1 -TargetMailbox $socMailbox -TargetFolder "PROCESSING" -LogLevel Full
            if ( $messageCount -lt 10 ) {
                $searchMailboxResults2 = Search-Mailbox $endUserName -SearchQuery $messageQuery2 -TargetMailbox $socMailbox -TargetFolder "PROCESSING" -LogLevel Full
                $searchMailboxResults3 = Search-Mailbox $endUserName -SearchQuery $messageQuery3 -TargetMailbox $socMailbox -TargetFolder "PROCESSING" -LogLevel Full
            }
        }

        $quarantine = "NO"
        $caseStatus = "Email messages have been extracted to the Phishing Case Inbox ($socMailbox) for further analysis..."
        $messageStatus = "Extracted"

        Write-Output "Email messages have been extracted to the Phishing Case Inbox for further analysis..."

    }

}


# ================================================================================
# OFFICE365 ADMINISTRATIVE ACTIONS
# ================================================================================

if ( $resetPassword ) {

    if ( $targetMailbox ) {

        $newPassword = ([System.Web.Security.Membership]::GeneratePassword(16,2))
        Set-MsolUserPassword –UserPrincipalName $targetMailbox –NewPassword $newPassword -ForceChangePassword $True
        Write-Output "We've set the password for the account $targetMailbox to be $newPassword. Make sure you record this and share with the user, or be ready to reset the password again. They will have to reset their password on the next logon."
    
        #Set-MsolUser -UserPrincipalName $targetMailbox -StrongPasswordRequired $True
        #Write-Output "We've also set this user's account to require a strong password."

        $caseStatus = "We've set the password for the account $targetMailbox to be $newPassword. Ensure that they change this immediately!"

    } else {
        Write-Output ""
        Write-Output "Target Mailbox Required ( -targetMailbox )"
        break;
    }
}

if ( $blockSender ) {
    
    if ( $sender ) {

        if ( $recipient ) {

            Write-Output ""
            Write-Output "Blocking ($sender) from sending mail to ($recipient)."
            Write-Output ""

            $Temp = Get-MailboxJunkEmailConfiguration $recipient
            $Temp.BlockedSendersAndDomains += "$sender"
            Set-MailboxJunkEmailConfiguration -Identity $recipient -BlockedSendersAndDomains $Temp.BlockedSendersAndDomains
            $blockList = Get-MailboxJunkEmailConfiguration -Identity $recipient | Select-Object BlockedSendersAndDomains
            $blockList = @($blockList | findstr -v "BlockedSendersAndDomains -----")
            Write-Output "     [ + ] $recipient || $blockList" -ForegroundColor Cyan
            Write-Output ""
        
        } else {
            
            Get-MessageTrace -SenderAddress $sender -StartDate $48Hours -EndDate $date | Select MessageTraceID,Received,*Address,*IP,Subject,Status,Size,MessageID | Export-Csv $tmpLog -NoTypeInformation
            type $tmpLog | findstr -v "MessageTraceId" > $analysisLog
            $messageCount = type $analysisLog | findstr -i $sender | Measure-Object | Select-Object Count | findstr -v "Count -"
            $messageCount = $messageCount.Trim() -match "[0-9+]"
            $spammer = $sender
            type $analysisLog | ForEach-Object { $_.Split(",")[3]  } | Sort | Get-Unique | findstr "@" > $tmPIEfolder\recipients.txt
            
            Write-Output ""
            Write-Output "Blocking ($sender) from sending mail to $messageCount recipients. This may take a few minutes..."
            Write-Output ""

            $getUsers = type $tmPIEfolder\recipients.txt
            $recipients = $getUsers.Split('"')[1]

            $messageRecipients = (Get-Content "$tmPIEfolder\recipients.txt") -join ", "
            $messageRecipients = $messageRecipients -replace '"', ""

            foreach ($phishRecipient in $getUsers) {
        
                try {

                    $phishRecipient = $phishRecipient.Split('"')[1]
                    $endUserName = $phishRecipient.Split("@")[0]
                    $Temp = Get-MailboxJunkEmailConfiguration $phishRecipient
                    $Temp.BlockedSendersAndDomains += "$sender"
                    
                    Set-MailboxJunkEmailConfiguration -Identity $endUserName -BlockedSendersAndDomains $Temp.BlockedSendersAndDomains
                    $blockList = Get-MailboxJunkEmailConfiguration -Identity $endUserName | Select-Object BlockedSendersAndDomains
                    $blockList = @($blockList | findstr -v "BlockedSendersAndDomains -----")

                    Write-Output "     [ + ] $phishRecipient || Successfully added ($sender) to this users block list" -ForegroundColor Cyan
                    
                    # v----- This is risky - can result in overwriting the entire company's block lists! -----v
                    #Get-Mailbox -ResultSize Unlimited | Set-MailboxJunkEmailConfiguration -BlockedSendersAndDomains $sender

                } catch {
                    Write-Output "Error - unable to block $sender for $phishRecipient!"
                }
            
            }

            Write-Output ""
            Write-Output "Sender ($sender) successfully blocked for $messageCount users"
            Write-Output ""
        
        }

    } else {
        Write-Output ""
        Write-Output "Sender Email Address Required ( -sender )"
        break;
    }
}


# ================================================================================
# LOGRHYTHM CASE MANAGEMENT
# ================================================================================

if ( $caseAPItoken ) {

    #force TLS v1.2 required by caseAPI
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Ignore invalid SSL certification warning
add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

    $token = "Bearer $caseAPItoken"
    $caseURL = "https://$LogRhythmHost/api/cases/"
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-type", "application/json")
    $headers.Add("Authorization", $token)

    if ( $scrapeMail ) {
        
        $casePriority = "2"
        $spammerName = $spammer.Split("@")[0]
        $spammerDomain = $spammer.Split("@")[1]
    
        # Define the case summary
        $caseName = "Email $messageStatus : $spammerName [at] $spammerDomain"
        $caseSummary = "Email from $spammer has been quarantined and extracted for analysis on $day via LogRhythm SmartResponse. $caseQuery Initial analysis shows that $messageCount user(s) received this email in the past $timeframe."

        # Create Case if one doesn't already exist
        if ( -Not $caseNumber ) {

            # CREATE CASE
            
            $payload = "{ `"name`": `"$caseName`", `"priority`": $casePriority, `"summary`": `"$caseSummary`" }"
            $output = Invoke-RestMethod -uri $caseURL -headers $headers -Method POST -body $payload
            $caseNumber = $output.number
            $noteurl = $caseURL + "number/$caseNumber/evidence/note"
            sleep 5

            # Update Case with raw logs
            $caseNote = type $analysisLog
            $caseNote = $caseNote -replace '"', ""
            $note = "Raw Phishing Logs: $caseNote"
            
            $payload = "{ `"text`": `"$note`" }"
            Invoke-RestMethod -uri $noteurl -headers $headers -Method POST -body $payload

            # Append List of Email Recipients
            $messageRecipients = (Get-Content "$tmPIEfolder\recipients.txt") -join ", "
            $messageRecipients = $messageRecipients -replace '"', ""
            $note = "Email Recipients: $messageRecipients"
            
            $payload = "{ `"text`": `"$note`" }"
            Invoke-RestMethod -uri $noteurl -headers $headers -Method POST -body $payload
        
        }

        # Update Case status
        $note = "$caseStatus"
        $noteurl = $caseURL + "number/$caseNumber/evidence/note"
        $payload = "{ `"text`": `"$note`" }"
        Invoke-RestMethod -uri $noteurl -headers $headers -Method POST -body $payload

    }

    if ( $resetPassword ) {
        
        $casePriority = "3"

        # Define the case summary
        $caseName = "Office 365 Account Credentials Reset: $targetMailbox"
        $caseSummary = "We've set the password for the account $targetMailbox to be $newPassword. Make sure you record this and share with the user, or be ready to reset the password again. They will have to reset their password on the next logon."

        # Create Case if one doesn't already exist
        if ( -Not $caseNumber ) {

            # CREATE CASE
            
            $payload = "{ `"name`": `"$caseName`", `"priority`": $casePriority, `"summary`": `"$caseSummary`" }"
            $output = Invoke-RestMethod -uri $caseURL -headers $headers -Method POST -body $payload
            $caseNumber = $output.number
            sleep 5

        }

        # Update Case status
        $note = "($recipient) Credentials Reset - Please communicate this change with the affected user!"
        $noteurl = $caseURL + "number/$caseNumber/evidence/note"
        $payload = "{ `"text`": `"$note`" }"
        Invoke-RestMethod -uri $noteurl -headers $headers -Method POST -body $payload

    }

    if ( $blockSender ) {

        $casePriority = "5"
        
        # Define the case summary
        $caseSummary = "Blacklisted Sender : $sender"
        $caseNote = "($sender) has been banned from sending further mail to the organization. Review the black list within the Office 365 Management Interface."

        # Create Case if one doesn't already exist
        if ( -Not $caseNumber ) {
            
            # CREATE CASE
            
            $payload = "{ `"name`": `"$caseName`", `"priority`": $casePriority, `"summary`": `"$caseSummary`" }"
            $output = Invoke-RestMethod -uri $caseURL -headers $headers -Method POST -body $payload
            $caseNumber = $output.number
            sleep 5
            
        }

        if ( $recipient ) {
            $caseStatus = "The sender ($sender) has been blocked from sending ($recipient) further messages"
        } else {
            $messageRecipients = (Get-Content "$tmPIEfolder\recipients.txt") -join ", "
            $messageRecipients = $messageRecipients -replace '"', ""
            $caseStatus = "The sender ($sender) has been blocked from sending further messages to $messageCount email addresses: $messageRecipients"
        }
        
        # Update Case status
        $note = "$caseStatus"
        $noteurl = $caseURL + "number/$caseNumber/evidence/note"
        $payload = "{ `"text`": `"$note`" }"
        Invoke-RestMethod -uri $noteurl -headers $headers -Method POST -body $payload

    }

    Write-Output "Email Actions Completed and LogRhythm Case has been generated"
    Write-Output ""

}

# clean up and clear all variables
Remove-PSSession $Session
Remove-Item $tmPIEfolder -Force -Recurse
Get-Variable | Remove-Variable -EA 0