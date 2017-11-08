
  #====================================#
  #       Office 365 Ninja             #
  # LogRhythm Security Operations      #
  # greg . foss @ logrhythm . com      #
  # v1.0  --  October, 2017            #
  #====================================#

# Copyright 2017 LogRhythm Inc.   
# Licensed under the MIT License. See LICENSE file in the project root for full license information.

function Invoke-O365Ninja {

<#

SYNOPSIS:
    
    Collection of useful commands for easy integration with Office 365 and the LogRhythm SIEM
    Automate the full response to phishing attacks by dynamically blocking and quarantining delivered mail

USAGE:

    Run the following command for a list of options associated with this script:

        PS C:\> Invoke-O365Ninja -help

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
    [switch]$help,
    [switch]$scrapeMail,
    [switch]$getMail,
    [switch]$resetPassword,
    [switch]$blockSender,
    [switch]$unblockSender,
    [switch]$checkForwards,
    [switch]$bypass,
    [switch]$nuke = $false
)


$banner = @"
   ___ ____  __ ___   _  _ _       _      
  / _ \__ / / /| __| | \| (_)_ _  (_)__ _ 
 | (_) |_ \/ _ \__ \ | .' | | ' \ | / _' |
  \___/___/\___/___/ |_|\_|_|_||_|/ \__,_|
                                |__/      
"@

$usage = @"
USAGE:

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

    Block Sender for the whole company:
    PS C:\> Invoke-O365Ninja -blockSender -sender "<spammer>"

    Remove Sender from block list for specific user:
    PS C:\> Invoke-O365Ninja -unblockSender -sender "<not spammer>" -recipient "<recipient>"

    Remove Sender from block list for the whole company:
    PS C:\> Invoke-O365Ninja -unblockSender -sender "<not spammer>"
    
    Reset End User's Password:
    PS C:\> Invoke-O365Ninja -resetPassword -targetMailbox "User.Name"

    Check Auto Forwarding Rules:
    PS C:\> Invoke-O365Ninja -checkForwards

    ************************************************************

    All arguments require administrative access to Office 365, and must include the following parameters / supply them at runtime
        -username, -password, -socMailbox

    To take advantage of the LogRhythm SIEM integrations, the following parameters are required
        -LogRhythmHost, -caseAPIToken, -caseNumber (optional - if not supplied a new case will be created)
"@

if ( $help ) {

    Write-Host $banner -ForegroundColor Green
    Write-Host $usage
    Write-Host ""
    break;
    
}

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

Write-Host $banner -ForegroundColor Green
Write-Host ""

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
    Write-Host "Access Denied..."
    Write-Host ""
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
        Write-Host "Target User not specified (-targetUser)" -ForegroundColor Red
        Write-Host ""
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

            if ( $bypass ) {
                Write-Host "Warning - Quarantining mail from internal employee ($sender)!" -ForegroundColor Yellow
                Write-Host ""
            } else {
                Write-Host "Error - unable to quarantine mail from $sender as they appear to be an internal employee!" -ForegroundColor Red
                Write-Host "If you are sure that you would like to proceed, run the script with the -bypass flag set" -ForegroundColor Red
                Write-Host ""
                break;
            }

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

            if ( $bypass ) {
                Write-Host "Warning - Quarantining mail from internal employee ($sender)!" -ForegroundColor Yellow
                Write-Host ""
            } else {
                Write-Host "Error - unable to quarantine mail from $sender as they appear to be an internal employee!" -ForegroundColor Red
                Write-Host "If you are sure that you would like to proceed, run the script with the -bypass flag set" -ForegroundColor Red
                Write-Host ""
                break;
            }

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

            if ( $bypass ) {
                Write-Host "Warning - Quarantining mail from internal employee ($sender)!" -ForegroundColor Yellow
                Write-Host ""
            } else {
                Write-Host "Error - unable to quarantine mail from $sender as they appear to be an internal employee!" -ForegroundColor Red
                Write-Host "If you are sure that you would like to proceed, run the script with the -bypass flag set" -ForegroundColor Red
                Write-Host ""
                break;
            }

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

        echo ""
        echo "Phishing messages have been quarantined and samples have been extracted to the Phishing Case Inbox for further analysis..."
        echo ""
        echo "$messageCount - Total Recipients:"
        echo ""
        echo "$getUsers"
        echo ""

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

        echo ""
        echo "Email messages have been extracted to the Phishing Case Inbox for further analysis..."
        echo "To delete the emails run the following PowerShell command:"
        echo ""
        echo 'PS C:\> Search-Mailbox <end username> -SearchQuery <message query> -TargetMailbox <soc mailbox> -TargetFolder "PROCESSING" -DeleteContent -Force'echo ""
        echo "$messageCount - Total Recipients:"
        echo ""
        echo "$getUsers"
        echo ""

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
        Write-Host ""
        Write-Host "Target Mailbox Required ( -targetMailbox )" -ForegroundColor Red
        break;
    }
}

if ( $blockSender ) {
    
    if ( $sender ) {

        if ( $recipient ) {

            Write-Host ""
            Write-Host "Blocking ($sender) from sending mail to ($recipient)."
            Write-Host ""

            try {

                Set-MailboxJunkEmailConfiguration -Identity $recipient -BlockedSendersAndDomains @{Add="$sender"}
                Write-Host "     [ + ] $recipient || $sender Blocked Successfully" -ForegroundColor Cyan
                Write-Host ""

            } catch {
                
                Write-Host "     [ - ] $recipient || Unable to block $sender..." -ForegroundColor Cyan
                Write-Host ""
            
            }
        
        } else {
            
            Get-MessageTrace -SenderAddress $sender -StartDate $48Hours -EndDate $date | Select MessageTraceID,Received,*Address,*IP,Subject,Status,Size,MessageID | Export-Csv $tmpLog -NoTypeInformation
            type $tmpLog | findstr -v "MessageTraceId" > $analysisLog
            $messageCount = type $analysisLog | findstr -i $sender | Measure-Object | Select-Object Count | findstr -v "Count -"
            $messageCount = $messageCount.Trim() -match "[0-9+]"
            $spammer = $sender
            type $analysisLog | ForEach-Object { $_.Split(",")[3]  } | Sort | Get-Unique | findstr "@" > $tmPIEfolder\recipients.txt
            
            Write-Host ""
            Write-Host "Blocking ($sender) from sending mail to $messageCount recipients. This may take a few minutes..."
            Write-Host ""

            $getUsers = type $tmPIEfolder\recipients.txt
            $recipients = $getUsers.Split('"')[1]

            $messageRecipients = (Get-Content "$tmPIEfolder\recipients.txt") -join ", "
            $messageRecipients = $messageRecipients -replace '"', ""

            foreach ($phishRecipient in $getUsers) {
        
                $phishRecipient = $phishRecipient.Split('"')[1]
                $endUserName = $recipient.Split("@")[0]    

                try {

                    Set-MailboxJunkEmailConfiguration -Identity $phishRecipient -BlockedSendersAndDomains @{Add="$sender"}
                    Write-Host "     [ + ] $phishRecipient || $sender Blocked Successfully" -ForegroundColor Cyan

                } catch {
                
                    Write-Host "     [ - ] $phishRecipient || Unable to block $sender..." -ForegroundColor Red
                    Write-Host ""
            
                }
            
            }

            Write-Host ""
            Write-Host "Sender ($sender) successfully blocked for $messageCount users!"
            Write-Host ""
        
        }

    } else {
        Write-Host ""
        Write-Host "Sender Email Address Required ( -sender )" -ForegroundColor Red
        break;
    }
}

if ( $unblockSender ) {
    
    if ( $sender ) {

        if ( $recipient ) {

            Write-Host ""
            Write-Host "Unblocking ($sender) for recipient ($recipient)."
            Write-Host ""

            $phishRecipient = $recipient.Split('"')[1]
            $endUserName = $recipient.Split("@")[0]
            
            try {

                Set-MailboxJunkEmailConfiguration -Identity $phishRecipien -BlockedSendersAndDomains @{Remove="$sender"}
                Write-Host "     [ + ] $recipient || $sender Unblocked Successfully" -ForegroundColor Cyan
                Write-Host ""
                break;

            } catch {
                
                Write-Host "     [ - ] $recipient || Unable to unblock $sender..." -ForegroundColor Red
                Write-Host ""
                break;
            
            }
        
        } else {
            
            Get-MessageTrace -SenderAddress $sender -StartDate $48Hours -EndDate $date | Select MessageTraceID,Received,*Address,*IP,Subject,Status,Size,MessageID | Export-Csv $tmpLog -NoTypeInformation
            type $tmpLog | findstr -v "MessageTraceId" > $analysisLog
            $messageCount = type $analysisLog | findstr -i $sender | Measure-Object | Select-Object Count | findstr -v "Count -"
            $messageCount = $messageCount.Trim() -match "[0-9+]"
            $spammer = $sender
            type $analysisLog | ForEach-Object { $_.Split(",")[3]  } | Sort | Get-Unique | findstr "@" > $tmPIEfolder\recipients.txt
            
            Write-Host ""
            Write-Host "Unblocking ($sender) to allow mail to be sent to $messageCount recipients. This may take a few minutes..."
            Write-Host ""

            $getUsers = type $tmPIEfolder\recipients.txt
            $recipients = $getUsers.Split('"')[1]

            $messageRecipients = (Get-Content "$tmPIEfolder\recipients.txt") -join ", "
            $messageRecipients = $messageRecipients -replace '"', ""

            foreach ($phishRecipient in $getUsers) {
                
                $phishRecipient = $phishRecipient.Split('"')[1]
                $endUserName = $phishRecipient.Split("@")[0]

                try {

                    Set-MailboxJunkEmailConfiguration -Identity $endUserName -BlockedSendersAndDomains @{Remove="$sender"}
                    Write-Host "     [ + ] $phishRecipient || $sender Unblocked Successfully" -ForegroundColor Cyan

                } catch {
                
                    Write-Host "     [ - ] $phishRecipient || Unable to unblock $sender..." -ForegroundColor Red
                    Write-Host ""
            
                }
            
            }

            Write-Host ""
            Write-Host "Sender ($sender) successfully unblocked from sending mail to $messageCount users"
            Write-Host ""
            break;
        
        }

    } else {
        Write-Host ""
        Write-Host "Sender Email Address Required ( -sender )" -ForegroundColor Red
        break;
    }
}

if ( $checkForwards ) {

    Get-MailBox |?{$_.ForwardingAddress -ne $null}| Select-Object PrimarySmtpAddress,ForwardingAddress,ForwardingSmtpAddress,Office | Out-Gridview
    break;

}

# ================================================================================
# LOGRHYTHM CASE MANAGEMENT
# ================================================================================

if ( $caseAPItoken ) {

    Write-Host "LogRhythm Case Management"
    Write-Host "========================="

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
            Write-Host "Creating LogRhythm Case:"
            Write-Host "URL:: $LogRhythmHost"
            Write-Host "Name: $caseName"
            Write-Host "Pri:: $casePriority"
            Write-Host "Summary:: $caseSummary"
            
            $payload = "{ `"name`": `"$caseName`", `"priority`": $casePriority, `"summary`": `"$caseSummary`" }"
            $output = Invoke-RestMethod -uri $caseURL -headers $headers -Method POST -body $payload
            $caseNumber = $output.number
            $noteurl = $caseURL + "number/$caseNumber/evidence/note"
            sleep 5

            # Update Case with raw logs
            $caseNote = type $analysisLog
            $caseNote = $caseNote -replace '"', ""
            $note = "Raw Phishing Logs: $caseNote"
            
            Write-Host "Adding Case Note: $noteurl"
            $payload = "{ `"text`": `"$note`" }"
            Write-Host "Json: $payload"
            Invoke-RestMethod -uri $noteurl -headers $headers -Method POST -body $payload

            # Append List of Email Recipients
            $messageRecipients = (Get-Content "$tmPIEfolder\recipients.txt") -join ", "
            $messageRecipients = $messageRecipients -replace '"', ""
            $note = "Email Recipients: $messageRecipients"
            
            Write-Host "Adding Case Note: $noteurl"
            $payload = "{ `"text`": `"$note`" }"
            Write-Host "Json: $payload"
            Invoke-RestMethod -uri $noteurl -headers $headers -Method POST -body $payload

        }

        # Update Case status
        $note = "$caseStatus"
        $noteurl = $caseURL + "number/$caseNumber/evidence/note"
        Write-Host "Adding Case Note: $noteurl"
        $payload = "{ `"text`": `"$note`" }"
        Write-Host "Json: $payload"
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
            Write-Host "Creating LogRhythm Case:"
            Write-Host "URL:: $LogRhythmHost"
            Write-Host "Name: $caseName"
            Write-Host "Pri:: $casePriority"
            Write-Host "Summary:: $caseSummary"
            
            $payload = "{ `"name`": `"$caseName`", `"priority`": $casePriority, `"summary`": `"$caseSummary`" }"
            $output = Invoke-RestMethod -uri $caseURL -headers $headers -Method POST -body $payload
            $caseNumber = $output.number
            sleep 5

        }

        # Update Case status
        $note = "($recipient) Credentials Reset - Please communicate this change with the affected user!"
        $noteurl = $caseURL + "number/$caseNumber/evidence/note"
        Write-Host "Adding Case Note: $noteurl"
        $payload = "{ `"text`": `"$note`" }"
        Write-Host "Json: $payload"
        Invoke-RestMethod -uri $noteurl -headers $headers -Method POST -body $payload

    }

    if ( $blockSender ) {

        $casePriority = "5"
        
        # Define the case summary
        $caseName = "Blacklisted Sender : $sender"
        $caseSummary = "($sender) has been banned from sending further mail to the organization. Review the black list within the Office 365 Management Interface."

        # Create Case if one doesn't already exist
        if ( -Not $caseNumber ) {
            
            # CREATE CASE
            Write-Host "Creating LogRhythm Case:"
            Write-Host "URL:: $LogRhythmHost"
            Write-Host "Name: $caseName"
            Write-Host "Pri:: $casePriority"
            Write-Host "Summary:: $caseSummary"
            
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
            $caseStatus = "The sender ($sender) has been blocked from sending further messages to $messageCount email addresses."
        }
        
        # Update Case status
        $note = "$caseStatus"
        $noteurl = $caseURL + "number/$caseNumber/evidence/note"
        Write-Host "Adding Case Note: $noteurl"
        $payload = "{ `"text`": `"$note`" }"
        Write-Host "Json: $payload"
        Invoke-RestMethod -uri $noteurl -headers $headers -Method POST -body $payload

    }

}


# clean up and clear all variables
Remove-PSSession $Session
Remove-Item $tmPIEfolder -Force -Recurse
Get-Variable | Remove-Variable -EA 0

}
