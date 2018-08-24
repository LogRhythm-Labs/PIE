
#====================================#
#    Office 365 Ninja - OS X         #
# LogRhythm Security Operations      #
# greg . foss @ logrhythm . com      #
# v2.0  --  August, 2018             #
#====================================#

# Copyright 2018 LogRhythm Inc.   
# Licensed under the MIT License. See LICENSE file in the project root for full license information.

function Invoke-O365Ninja {

<#

SYNOPSIS:
    
    Collection of useful commands for easy integration with Office 365 and the LogRhythm SIEM
    Automate the full response to phishing attacks by dynamically blocking and quarantining delivered mail

USAGE:

    Run the following command for a list of options associated with this script:

        PS /> Invoke-O365Ninja -help

#>

[CmdLetBinding()]
param( 
    [string]$username,
    [string]$password,
    [string]$encodedXMLCredentials,
    [string]$socMailbox,
    [string]$LogRhythmHost,
    [string]$caseAPItoken,
    [string]$caseNumber,
    [string]$addCaseUser,
    [string]$targetUser,
    [string]$fromIP,
    [string]$sender,
    [string]$recipient,
    [string]$subject,
    [string]$past,
    [string]$spammerList,
    [string]$defaultCaseTag = "phishing", # default tag for case management
    [switch]$help,
    [switch]$searchMail,
    [switch]$scrapeMail,
    [switch]$getMail,
    [switch]$auditLog,
    [switch]$resetPassword,
    [switch]$blockSender,
    [switch]$unblockSender,
    [switch]$appendToList,
    [switch]$checkForwards,
    [switch]$checkMemberships,
    [switch]$bypass,
    [switch]$nuke = $false
)


$banner = @"
     ___ ____  __ ___   _  _ _       _      
    / _ \__ / / /| __| | \| (_)_ _  (_)__ _ 
    | (_) |_ \/ _ \__ \ | .' | | ' \ | / _' |
    \___/___/\___/___/ |_|\_|_|_||_|/ \__,_|  OSX
                                |__/      
"@

$usage = @"
USAGE:

    Search through mail logs:
    PS C:\> Invoke-O365Ninja -searchMail

    Available switches for mail search:
        -sender, -recipient, -fromIP

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

    Add Spammer to Threat List:
    PS C:\> Invoke-O365Ninja -appendToList -sender "<sender@email>" -spammerList "<LogRhythm List Name>"
    
    Check Auto Forwarding Rules:
    PS C:\> Invoke-O365Ninja -checkForwards

    Obtain Group Memberships:
    PS C:\> Invoke-O365Ninja -checkMemberships

    ************************************************************

    All arguments require administrative access to Office 365, and must include the following parameters / supply them at runtime
        -username, -password, -socMailbox

        -encodedXMLCredentials "C:\File-location.xml"

        This value can be used if you would like to store your credentials in an encoded XML file

    To take advantage of the LogRhythm SIEM integrations, the following parameters are required
        -LogRhythmHost, -appendToList, -spammerList -caseAPIToken, -caseNumber (optional - if not supplied a new case will be created)
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
$currentFolder = (Get-Item -Path "./" -Verbose).FullName
$tmPIEfolder = "$currentFolder/TemporaryPIE/"
mkdir $tmPIEfolder > $null

$traceLog = "$tmPIEfolder/ongoing-trace-log.csv"
$phishLog = "$tmPIEfolder/ongoing-phish-log.csv"
$analysisLog = "$tmPIEfolder/analysis.csv"
$tmpLog = "$tmPIEfolder/srp-tmp.csv"
$tmpFolder = "$tmPIEfolder/tmp/"

Write-Host $banner -ForegroundColor Green
Write-Host ""

# ================================================================================
# Office 365 API Authentication
# ================================================================================

if ( $encodedXMLCredentials ) {

# XML Configuration - store credentials in an encoded XML file
#     This file will need to be re-generated whenever your system reboots!
#
#     To generate the XML:
#          PS /> Get-Credential | Export-Clixml Service-Account_cred.xml

    $CredentialsFile = "$encodedXMLCredentials"
    try {
        $cred = Import-Clixml -Path $CredentialsFile
        $Username = $cred.Username
        $Password = $cred.GetNetworkCredential().Password
    } catch {
        Write-Error ("Could not find credentials file: " + $CredentialsFile)
        Break;
    }
}

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

    if ( -Not $socMailbox ) {
        Write-Host "Target mailbox -socMailbox is required for this option" -ForegroundColor Red
        Break;
    }
    
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


if ( $searchMail ) {

    if ( $fromIP ) {
        Write-Host "================================"
        Get-MessageTrace -FromIP $fromIP -StartDate $48Hours -EndDate $date | Select Received,*Address,*IP,Subject,Status | Format-Table
        Write-Host "================================"
        break;
    }

    if ( $sender ) {
        Write-Host "================================"
        Get-MessageTrace -SenderAddress $sender -StartDate $48Hours -EndDate $date | Select Received,*Address,*IP,Subject,Status | Format-Table
        Write-Host "================================"
        break;
    }

    if ( $recipient ) {
        Write-Host "================================"
        Get-MessageTrace -RecipientAddress $recipient -StartDate $48Hours -EndDate $date | Select Received,*Address,*IP,Subject,Status | Format-Table
        Write-Host "================================"
        break;
    }
}


if ( $scrapeMail ) {

    if ( -Not $socMailbox ) {
        Write-Host "Target mailbox -socMailbox is required for this option" -ForegroundColor Red
        Break;
    }
    
    if ( $fromIP ) {
        
        Get-MessageTrace -FromIP $fromIP -StartDate $48Hours -EndDate $date | Select MessageTraceID,Received,*Address,*IP,Subject,Status,Size,MessageID | Export-Csv $tmpLog -NoTypeInformation
        type $tmpLog | findstr -v "MessageTraceId" > $analysisLog
        $messageCount = type $analysisLog | findstr -i $sender | Measure-Object | Select-Object Count | findstr -v "Count -"
        $messageCount = $messageCount.Trim() -match "[0-9+]"
        type $analysisLog | ForEach-Object { $_.Split(",")[3]  } | Sort | Get-Unique | findstr "@" > $tmPIEfolder/recipients.txt
        #$messageQuery1 = "from:" + '"' + $sender + '"' + " Sent:" + $today
        #$messageQuery2 = "from:" + '"' + $sender + '"' + " Sent:" + $yesterday
        #$messageQuery3 = "from:" + '"' + $sender + '"' + " Sent:" + $dayBefore

        $caseQuery = "Malicious Emails Sent from IP Address ($fromIP)"
        if ( $messageCount -lt 10 ) {
            $timeframe = "48 hours"
        } else {
            $timeframe = "12 hours"
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
            type $analysisLog | ForEach-Object { $_.Split(",")[3]  } | Sort | Get-Unique | findstr "@" > $tmPIEfolder/recipients.txt
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
        
            type $analysisLog | ForEach-Object { $_.Split(",")[3]  } | Sort | Get-Unique | findstr "@" > $tmPIEfolder/recipients.txt
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
        
            type $analysisLog | ForEach-Object { $_.Split(",")[3]  } | Sort | Get-Unique | findstr "@" > $tmPIEfolder/recipients.txt
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

    if ( $nuke -eq $true ) {
    
        $getUsers = type $tmPIEfolder/recipients.txt
        
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

        $getUsers = type $tmPIEfolder/recipients.txt
    
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
        echo 'PS /> Search-Mailbox <end username> -SearchQuery <message query> -TargetMailbox <soc mailbox> -TargetFolder "PROCESSING" -DeleteContent -Force'echo ""
        echo "$messageCount - Total Recipients:"
        echo ""
        echo "$getUsers"
        echo ""

    }

}


# ================================================================================
# OFFICE365 AUDIT LOG SEARCHING
# ================================================================================

if ( $auditLog ) {

    if ( $targetUser ) {
        
        Write-Host ""
        Write-Host "Audit Log Search for ($targetUser)"
        Search-MailboxAuditLog -identity $targetUser -logontypes admin,delegate,owner -startdate $48Hours -enddate $today -resultsize 5000 -ShowDetails | Out-GridView
    
    } else {
        Write-Host ""
        Write-Host "Target User Account Required ( -targetUser )" -ForegroundColor Red
        break;
    }
}


# ================================================================================
# OFFICE365 ADMINISTRATIVE ACTIONS
# ================================================================================

if ( $resetPassword ) {

    if ( $targetUser ) {

        $newPassword = ([System.Web.Security.Membership]::GeneratePassword(16,2))
        Set-MsolUserPassword –UserPrincipalName $targetUser –NewPassword $newPassword -ForceChangePassword $True
        Write-Output "We've set the password for the account $targetUser to be $newPassword. Make sure you record this and share with the user, or be ready to reset the password again. They will have to reset their password on the next logon."
    
        #Set-MsolUser -UserPrincipalName $targetMailbox -StrongPasswordRequired $True
        #Write-Output "We've also set this user's account to require a strong password."

        $caseStatus = "We've set the password for the account $targetUser to be $newPassword. Ensure that they change this immediately!"

    } else {
        Write-Host ""
        Write-Host "Target User Account Required ( -targetUser )" -ForegroundColor Red
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
            type $analysisLog | ForEach-Object { $_.Split(",")[3]  } | Sort | Get-Unique | findstr "@" > $tmPIEfolder/recipients.txt
            
            Write-Host ""
            Write-Host "Blocking ($sender) from sending mail to $messageCount recipients. This may take a few minutes..."
            Write-Host ""

            $getUsers = type $tmPIEfolder/recipients.txt
            $recipients = $getUsers.Split('"')[1]

            $messageRecipients = (Get-Content "$tmPIEfolder/recipients.txt") -join ", "
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
            type $analysisLog | ForEach-Object { $_.Split(",")[3]  } | Sort | Get-Unique | findstr "@" > $tmPIEfolder/recipients.txt
            
            Write-Host ""
            Write-Host "Unblocking ($sender) to allow mail to be sent to $messageCount recipients. This may take a few minutes..."
            Write-Host ""

            $getUsers = type $tmPIEfolder/recipients.txt
            $recipients = $getUsers.Split('"')[1]

            $messageRecipients = (Get-Content "$tmPIEfolder/recipients.txt") -join ", "
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

if ( $checkMemberships ) {

    Get-UnifiedGroup | Sort-Object GroupMemberCount -Descending | Select-Object DisplayName,PrimarySmtpAddress,ManagedBy,GroupMemberCount,GroupExternalMemberCount,WhenCreated,WhenChanged,Notes | Out-GridView
    $Groups = Get-UnifiedGroup -Filter {GroupExternalMemberCount -gt 0}
    
    if ( $groups -gt 0 ) {
        Write-Host "External Group Memberships Detected" -ForegroundColor Red
        ForEach ($member in $groups) { 
            $ext = Get-UnifiedGroupLinks -Identity $member.Identity -LinkType Members
            ForEach ($e in $ext) {
                If ($e.Name -match "#EXT#")
                { Write-Host "Group " $member.DisplayName "includes guest user" $member.Name -ForegroundColor Cyan }
            }
        }
        Write-Host ""
    } else {
        Write-Host "No External Group Memberships Detected" -ForegroundColor Cyan
        Write-Host ""
    }

    break;

}

# ================================================================================
# LOGRHYTHM CASE AND LIST MANAGEMENT
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
    $caseURL = "https://$LogRhythmHost/lr-case-api/cases/"
    $listUrl = "https://$LogRhythmHost/lr-admin-api/lists/"
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-type", "application/json")
    $headers.Add("Authorization", $token)
    $headers.Add("Count", "100000")
    $headers.Add("maxItemsThreshold", "10000")

    if ( $appendToList ) {
        
        if ( $spammerList ) {
            
            if ( $sender ) {
            
                Write-Host ""
                Write-Host "Append to List " -ForegroundColor Green
                Write-Host "================================"

                $output = irm -Uri $listURL -Headers $headers -Method GET
                $listGuid = @($output | Where-Object name -EQ "$spammerList").guid
                $listType = @($output | Where-Object name -EQ "$spammerList").listType

                if ( $listType -eq "GeneralValue" ) {
                    $listType = "StringValue"
                }

                $listUpdate = $listUrl + $listGuid + "/items/"
            
                # ListItemType: List,KnownService,Classification,CommonEvent,KnownHost,IP,IPRange,Location,MsgSource,
                # MsgSourceType,MPERule,Network,StringValue,Port,PortRange,Protocol,HostName,ADGroup,Entity,RootEntity,
                # DomainOrigin,Hash,Policy,VendorInfo,Result,ObjectType,CVE,UserAgent,ParentProcessId,ParentProcessName,
                # ParentProcessPath,SerialNumber,Reason,Status,ThreatId,ThreatName,SessionType,Action,ResponseCode,Identity

                $payload = @('{ "items": 
    [
    {
        "displayValue": "List",
        "expirationDate": null,
        "isExpired": false,
        "isListItem": false,
        "isPattern": false,
        "listItemDataType": "List",
        "listItemType": "' + $listType + '",
        "value": "' + $sender + '",
        "valueAsListReference": {}
    }
]}')
                try {
                
                    $output = Invoke-RestMethod -Uri $listUpdate -Headers $headers -Method POST -Body $payload

                    Write-Host "Successfully Appended " -NoNewline
                    Write-Host "$sender" -NoNewline -ForegroundColor Cyan
                    Write-Host " To List " -NoNewline
                    Write-Host "$spammerList"-ForegroundColor Cyan

                } catch {
                
                    Write-Host "Failed To Append " -ForegroundColor Red -NoNewline
                    Write-Host "$sender" -NoNewline
                    Write-Host " To List " -NoNewline -ForegroundColor Red
                    Write-Host "$spammerList"
                }

                Write-Host "================================"
                Write-Host ""

            } else {
                Write-Host "-sender variable is required for the blocklist" -ForegroundColor Red
            } 
        } else {
            Write-Host "-spammerList variable is required for the blocklist" -ForegroundColor Red
        }
    }
    

    Write-Host "LogRhythm Case Management" -ForegroundColor Green
    Write-Host "========================="


    if ( $scrapeMail ) {
        
        $casePriority = "2"
        $spammerName = $spammer.Split("@")[0]
        $spammerDomain = $spammer.Split("@")[1]
    
        # Define the case summary
        $caseName = "Email $messageStatus : $spammerName [at] $spammerDomain"
        $caseSummary = "Email from $spammer has been quarantined and extracted for analysis via LogRhythm SmartResponse. $caseQuery Initial analysis shows that $messageCount user(s) received this email in the past $timeframe."

        # Create Case if one doesn't already exist
        if ( -Not $caseNumber ) {

            # CREATE CASE
            $payload = "{ `"name`": `"$caseName`", `"priority`": $casePriority, `"summary`": `"$caseSummary`" }"
            $output = Invoke-RestMethod -Uri $caseURL -Headers $headers -Method POST -Body $payload
            $caseNumber = $output.number
            $noteurl = $caseURL + "number/$caseNumber/evidence/note"
            sleep 5
            
            Write-Host "Creating LogRhythm Case:"
            Write-Host "URL:: " -NoNewline
            Write-Host "$noteurl" -ForegroundColor Cyan
            Write-Host "Name: " -NoNewline 
            Write-Host "$caseName" -ForegroundColor Cyan
            Write-Host "Pri:: " -NoNewline
            Write-Host "$casePriority" -ForegroundColor Cyan
            Write-Host "Summary:: " -NoNewline
            Write-Host "$caseSummary" -ForegroundColor Cyan

            # Update Case with raw logs
            $caseNote = type $analysisLog
            $caseNote = $caseNote -replace '"', ""
            $note = "Raw Phishing Logs: $caseNote"
            
            Write-Host "Adding Case Note:"
            Write-Host "$note" -ForegroundColor Cyan
            $payload = "{ `"text`": `"$note`" }"
            $output = Invoke-RestMethod -uri $noteurl -headers $headers -Method POST -body $payload

            # Append List of Email Recipients
            $messageRecipients = (Get-Content "$tmPIEfolder/recipients.txt") -join ", "
            $messageRecipients = $messageRecipients -replace '"', ""
            $note = "Email Recipients: $messageRecipients"
            
            Write-Host "Appending List of Recipients to the case:"
            Write-Host "$note" -ForegroundColor Cyan
            $payload = "{ `"text`": `"$note`" }"
            $output = Invoke-RestMethod -uri $noteurl -headers $headers -Method POST -body $payload

            # Send the datas
            $output = Invoke-RestMethod -Uri $caseURL -Headers $headers -Method GET
            $output = $output | Select-Object number, id | Where-Object number -EQ $caseNumber
            $caseUUID = $output.id

            # Tag The Case
            $tagUrl = "https://$LogRhythmHost/lr-case-api/tags/"
            $output = Invoke-RestMethod -Uri $tagUrl -Headers $headers -Method GET
            $tagNumber = @($output | Select-Object number, text | Where-Object text -EQ "$defaultCaseTag").number
            $tagUrl = $caseUrl + "/$caseUUID/actions/addTags"

            Write-Host "Tagging Case $caseNumber:: " -NoNewline
            Write-Host "`"$defaultCaseTag`"" -ForegroundColor Cyan

            $payload = "{ `"numbers`": `[$tagNumber`] }"
            $output = Invoke-RestMethod -Uri $tagUrl -Headers $headers -Method PUT -Body $payload
        }

        # Update Case status
        $note = "$caseStatus"
        $noteurl = $caseURL + "number/$caseNumber/evidence/note"
        Write-Host "Adding Case Note:"
        Write-Host "$note" -ForegroundColor Cyan
        $payload = "{ `"text`": `"$note`" }"
        $output = Invoke-RestMethod -uri $noteurl -headers $headers -Method POST -body $payload

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

            Write-Host "Creating LogRhythm Case:"
            Write-Host "URL:: " -NoNewline
            Write-Host "$noteurl" -ForegroundColor Cyan
            Write-Host "Name: " -NoNewline 
            Write-Host "$caseName" -ForegroundColor Cyan
            Write-Host "Pri:: " -NoNewline
            Write-Host "$casePriority" -ForegroundColor Cyan
            Write-Host "Summary:: " -NoNewline
            Write-Host "$caseSummary" -ForegroundColor Cyan

        }

        # Update Case status
        $note = "($recipient) Credentials Reset - Please communicate this change with the affected user!"
        $noteurl = $caseURL + "number/$caseNumber/evidence/note"
        Write-Host "Adding Case Note:"
        Write-Host "$note" -ForegroundColor Cyan
        $payload = "{ `"text`": `"$note`" }"
        $output = Invoke-RestMethod -uri $noteurl -headers $headers -Method POST -body $payload

        # Tag The Case
        $tagUrl = "https://$LogRhythmHost/lr-case-api/tags/"
        $output = Invoke-RestMethod -Uri $tagUrl -Headers $headers -Method GET
        $tagNumber = @($output | Select-Object number, text | Where-Object text -EQ "password reset").number
        $tagUrl = $caseUrl + "/$caseUUID/actions/addTags"

        Write-Host "Tagging Case $caseNumber:: " -NoNewline
        Write-Host "`"password reset`"" -ForegroundColor Cyan

        $payload = "{ `"numbers`": `[$tagNumber`] }"
        $output = Invoke-RestMethod -Uri $tagUrl -Headers $headers -Method PUT -Body $payload

    }

    if ( $blockSender ) {

        $casePriority = "5"
        
        # Define the case summary
        $caseName = "Blacklisted Sender : $sender"
        $caseSummary = "($sender) has been banned from sending further mail to the organization. Review the black list within the Office 365 Management Interface."

        # Create Case if one doesn't already exist
        if ( -Not $caseNumber ) {
            
            # CREATE CASE
            $payload = "{ `"name`": `"$caseName`", `"priority`": $casePriority, `"summary`": `"$caseSummary`" }"
            $output = Invoke-RestMethod -uri $caseURL -headers $headers -Method POST -body $payload
            $caseNumber = $output.number
            sleep 5

            Write-Host "Creating LogRhythm Case:"
            Write-Host "URL:: " -NoNewline
            Write-Host "$caseURL" -ForegroundColor Cyan
            Write-Host "Name: " -NoNewline 
            Write-Host "$caseName" -ForegroundColor Cyan
            Write-Host "Pri:: " -NoNewline
            Write-Host "$casePriority" -ForegroundColor Cyan
            Write-Host "Summary:: " -NoNewline
            Write-Host "$caseSummary" -ForegroundColor Cyan

        }

        if ( $recipient ) {
            $caseStatus = "The sender ($sender) has been blocked from sending ($recipient) further messages"
        } else {
            $messageRecipients = (Get-Content "$tmPIEfolder/recipients.txt") -join ", "
            $messageRecipients = $messageRecipients -replace '"', ""
            $caseStatus = "The sender ($sender) has been blocked from sending further messages to $messageCount email addresses."
        }
        
        # Update Case status
        $note = "$caseStatus"
        $noteurl = $caseURL + "number/$caseNumber/evidence/note"
        Write-Host "Adding Case Note:"
        Write-Host "$note" -ForegroundColor Cyan
        $payload = "{ `"text`": `"$note`" }"
        $output = Invoke-RestMethod -uri $noteurl -headers $headers -Method POST -body $payload

        # Tag The Case
        $tagUrl = "https://$LogRhythmHost/lr-case-api/tags/"
        $output = Invoke-RestMethod -Uri $tagUrl -Headers $headers -Method GET
        $tagNumber = @($output | Select-Object number, text | Where-Object text -EQ "sender blocked").number
        $tagUrl = $caseUrl + "/$caseUUID/actions/addTags"

        Write-Host "Tagging Case $caseNumber:: " -NoNewline
        Write-Host "`"sender blocked`"" -ForegroundColor Cyan

        $payload = "{ `"numbers`": `[$tagNumber`] }"
        $output = Invoke-RestMethod -Uri $tagUrl -Headers $headers -Method PUT -Body $payload

    }

    # Add Case User and assign ownership
    if ( $addCaseUser ) {
        $userLookup = "https://$LogRhythmHost/lr-case-api/persons/"
        $output = Invoke-RestMethod -Uri $userLookup -Headers $headers -Method GET
        $userNumber = @($output | Select-Object number, name | Where-Object name -EQ "$addCaseUser").number

        # Find Case UUID
        $output = Invoke-RestMethod -Uri $caseURL -Headers $headers -Method GET
        $output = $output | Select-Object number, id | Where-Object number -EQ $caseNumber
        $caseUUID = $output.id

        # Add Case User
        $userQuery = $caseURL + "/$caseUUID/actions/addCollaborators/"
        Write-Host "Adding user ID " -NoNewline
        Write-Host "`"$addCaseUser`" " -NoNewline -ForegroundColor Cyan
        Write-Host "to Case:: " -NoNewline
        Write-Host "`"$caseNumber`"" -ForegroundColor Cyan
        $payload = "{ `"numbers`": `[$userNumber`] }"
        $output = Invoke-RestMethod -Uri $userQuery -Headers $headers -Method PUT -Body $payload

        # Update Case Owner
        $userUpdate = $caseURL + "/$caseUUID/actions/changeOwner/"
        Write-Host "Changing case " -NoNewline
        Write-Host "`"$caseNumber`" " -NoNewline -ForegroundColor Cyan
        Write-Host "owner to:: " -NoNewline
        Write-Host "`"$addCaseUser`"" -ForegroundColor Cyan
        $payload = "{ `"number`": $userNumber }"
        $output = Invoke-RestMethod -Uri $userUpdate -Headers $headers -Method PUT -Body $payload
    }

}


# clean up and clear all variables
Remove-PSSession $Session
Remove-Item $tmPIEfolder -Force -Recurse
Get-Variable | Remove-Variable -EA 0

}
