
  #====================================#
  # PIE - Phishing Intelligence Engine #
  # LogRhythm Security Operations      #
  # greg . foss @ logrhythm . com      #
  # v2.0  --  August 2018              #
  #====================================#

# Copyright 2018 LogRhythm Inc.   
# Licensed under the MIT License. See LICENSE file in the project root for full license information.

<#

INSTALL:

    Review lines 43 through 89
        Add credentials under each specified section - Office 365 Connectivity and LogRhythm Case API Integration
        Define the folder where you will deploy the Invoke-O365MessageTrace.ps1 script from

    Review Lines 90 through 154
        For each setting that you would like to enable, change the value from $false to $true
        For each enabled third party plugin, set the API key and other required paramters

USAGE:

    Configure as a scheduled task to run every 5-minutes:
        C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -command "& 'C:\PIE_INSTALL_DIR\Invoke-O365Trace.ps1'"

#>

$banner = @"
   _ \   |     _)        |     _)                   _ _|         |          |  | _)                                      ____|               _)              
  |   |  __ \   |   __|  __ \   |  __ \    _' |       |   __ \   __|   _ \  |  |  |   _' |   _ \  __ \    __|   _ \      __|    __ \    _' |  |  __ \    _ \ 
  ___/   | | |  | \__ \  | | |  |  |   |  (   |       |   |   |  |     __/  |  |  |  (   |   __/  |   |  (      __/      |      |   |  (   |  |  |   |   __/ 
 _|     _| |_| _| ____/ _| |_| _| _|  _| \__, |     ___| _|  _| \__| \___| _| _| _| \__, | \___| _|  _| \___| \___|     _____| _|  _| \__, | _| _|  _| \___| 
                                         |___/                                      |___/                                             |___/                  
"@

# Mask errors
$ErrorActionPreference= 'silentlycontinue'


# ================================================================================
# DEFINE GLOBAL PARAMETERS AND CAPTURE CREDENTIALS
#
# ****************************** EDIT THIS SECTION ******************************
# ================================================================================

# Choose how to handle credentials - set the desired flag to $true
#     Be sure to set credentials or xml file location below
$EncodedXMLCredentials = $false
$PlainText = $true

# XML Configuration - store credentials in an encoded XML (best option)
#     This file will need to be re-generated whenever the server reboots!
if ( $EncodedXMLCredentials ) {
    #
    # To generate the XML:
    #      PS C:\> Get-Credential | Export-Clixml Service-Account_cred.xml
    #
    $CredentialsFile = "C:\Path-To-Credentials-File.xml"
}

# Plain Text Credentials (not recommended)
if ( $PlainText ) {
    $username = "SERVICE-ACCOUNT@SOMEDOMAIN.COM"
    $password = "PASSWORD"
}

# Mailbox where Phishing emails will be reported
$socMailbox = "phishing@somedomain.com"

# LogRhythm Case API Integration
$LogRhythmHost = "LR Web Console Domain/IP:8501"
$caseAPItoken = ""

# Threat List to update with known spammer email addresses. Set to $true if you'd like to automatically update threat lists
$spamTracker = $false
$spammerList = "List Name"

# Case Folder and Logging
$pieFolder = "C:\PIE\INSTALLATION\DIRECTORY"

# Case Tagging and User Assignment
$defaultCaseTag = "phishing" # Default value - modify to match your case tagging schema. If this value does not exist, the script will not add the parameter to the case.
$caseOwner = "" # Primary case owner / SOC lead
$caseCollaborators = ("lname1, fname1", "lname2, fname2") # Add as many users as you would like, separate them like so: "user1", "user2"...


# ================================================================================
# Third Party Analytics
# ================================================================================

# For each supported module, set the flag to $true and enter the associated API key

# Auto Quarantine or Auto Ban?
$autoQuarantine = $false # Auto quarantine and/or ban the sender
$subjectAutoQuarantine = $false # Auto quarantine and create a case if the email matches the subject line regex check
$autoBan = $false # Auto blacklist known-bad senders
$threatThreshold = 5 # Actions run when the threat score is greater than the 'threatThreshold' below

# Are Office 365 SafeLinks in use?
$safeLinks = $false

# General Link Analysis - No API key required and enabled by default
$linkRegexCheck = $true
$shortLink = $true
$sucuri = $true
$getLinkInfo = $true

# Domain Tools
$domainTools = $false
$DTapiUsername = ""
$DTapiKey = ""

# OpenDNS
$openDNS = $false
$openDNSkey =""

# VirusTotal
$virusTotal = $false
$virusTotalAPI = ""

# URL Void
$urlVoid = $false
$urlVoidIdentifier = ""
$urlVoidKey = ""

# PhishTank.com
$phishTank = $false
$phishTankAPI = ""

# Shodan.io
$shodan = $false
$shodanAPI = ""

# Screenshot Machine
$screenshotMachine = $false
$screenshotKey = ""

# Cisco AMP Threat Grid
$threatGrid = $false
$threatGridAPI = ""

# Wrike
$wrike = $false
$wrikeAPI = ""
$wrikeFolder = ""
$wrikeUser = ""

# ================================================================================
# END GLOBAL PARAMETERS
# ************************* DO NOT EDIT BELOW THIS LINE *************************
# ================================================================================


# ================================================================================
# Date, File, and Global Email Parsing
# ================================================================================

# Folder Structure
$traceLog = "$pieFolder\logs\ongoing-trace-log.csv"
$phishLog = "$pieFolder\logs\ongoing-phish-log.csv"
$spamTraceLog = "$pieFolder\logs\ongoing-outgoing-spam-log.csv"
$analysisLog = "$pieFolder\logs\analysis.csv"
$tmpLog = "$pieFolder\logs\tmp.csv"
$caseFolder = "$pieFolder\cases\"
$tmpFolder = "$pieFolder\tmp\"
$log = $true

# Date Variables
$date = Get-Date
$oldAF = (Get-Date).AddDays(-10)
$48Hours = (Get-Date).AddHours(-48)
$24Hours = (Get-Date).AddHours(-24)
$inceptionDate = (Get-Date).AddMinutes(-6)
$phishDate = (Get-Date).AddMinutes(-7)
$day = Get-Date -Format MM-dd-yyyy

# Email Parsing Varibles
$boringFiles = @('jpg', 'png', 'ico')    
$boringFilesRegex = [string]::Join('|', $boringFiles)
$interestingFiles = @('pdf', 'exe', 'zip', 'doc', 'docx', 'docm', 'xls', 'xlsx', 'xlsm', 'ppt', 'pptx', 'arj', 'jar', '7zip', 'tar', 'gz', 'html', 'js')
$interestingFilesRegex = [string]::Join('|', $interestingFiles)

# Outlook Folder Parsing
function GetSubfolders($Parent) {
    $folders = $Parent.Folders
    foreach ($folder in $folders) {
        $Subfolder = $Parent.Folders.Item($folder.Name)
        Write-Host($folder.Name)
        GetSubfolders($Subfolder)
    }
}

# Link and Domain Verification
$IPregex=‘(?<Address>((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))’


# ================================================================================
# Office 365 API Authentication
# ================================================================================

if ( $EncodedXMLCredentials ) {
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
    Import-PSSession $Session -AllowClobber
} Catch {
    Write-Error "Access Denied..."
    Break;
}


# ================================================================================
# MEAT OF THE PIE
# ================================================================================

if ( $log -eq $true) {

    # scrape all mail - ongiong log generation
    $messageTrace = Get-MessageTrace -StartDate $inceptionDate -EndDate $date | Select MessageTraceID,Received,*Address,*IP,Subject,Status,Size,MessageID | Sort-Object Received
    $messageTrace | Export-Csv $traceLog -NoTypeInformation -Append
    
    # scrape outbound spam tracking logs
    #$spamTrace = Get-MailDetailSpamReport -StartDate $inceptionDate -EndDate $date -Direction outbound | Select MessageTraceID,Received,*Address,*IP,Subject,Status,Size,MessageID | Sort-Object Received
    #$messageTrace | Export-Csv $spamTraceLog -NoTypeInformation -Append

    # Search for Reported Phishing Messages
    sleep 10
    $phishTrace = Get-MessageTrace -RecipientAddress $socMailbox -StartDate $inceptionDate -EndDate $date | Select MessageTraceID,Received,*Address,*IP,Subject,Status,Size,MessageID | Sort-Object Received
    $phishTrace | Export-Csv $tmpLog -NoTypeInformation
    type $tmpLog | findstr -i $socMailbox >> $phishLog
    $reportPhish = type $tmpLog | findstr -i $socMailbox
    #$phishCount = Get-Content $tmpLog | findstr -i $socMailbox | Measure-Object Line

    # Connect to local inbox and check for new mail
    $outlookInbox = 6
    $outlook = new-object -com outlook.application
    $ns = $outlook.GetNameSpace("MAPI")
    $rootFolders = $ns.Folders | ?{$_.Name -match $env:phishing}
    $inbox = $ns.GetDefaultFolder($outlookInbox)
    $messages = $inbox.items
    $phishCount = $messages.count

    # Quick Subject line check for common tactics:
    if ( $subjectAutoQuarantine -eq $true ) {
    
        $subjectRegex = 'has\ been\ limited',
                        'We\ have\ locked',
                        'has\ been\ suspended',
                        'unusual\ activity',
                        'notifications\ pending',
                        'your\ (customer\ )?account\ has',
                        'your\ (customer\ )?account\ was',
                        'Periodic\ Maintenance',
                        'refund\ not\ approved',
                        'account\ (is\ )?on\ hold',
                        'wire\ transfer',
                        'secure\ update',
                        'temporar(il)?y\ deactivated',
                        'verification\ required'
                        #'new voice(\ )?mail'

        $subjects =  type $tmpLog
        $subjects | ForEach-Object {
            If([string]$_ -match ($subjectRegex -join "|")) {
                # Autoquarantine!
                $subjectQuarantineNote = "Initiating auto-quarantine based on suspicious email subject RegEx matching. Copying messages to the Phishing inbox and hard-deleting from all recipient inboxes."
                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$subjextQuarantineNote" -token $caseAPItoken
                sleep 5
                if ( $EncodedXMLCredentials ) {
                    & $pieFolder\plugins\O365Ninja.ps1 -scrapeMail -sender "$spammer" -nuke -encodedXMLCredentials "$EncodedXMLCredentials" -socMailbox $socMailBox -LogRhythmHost $LogRhythmHost -caseAPItoken $caseAPItoken
                } else {
                    & $pieFolder\plugins\O365Ninja.ps1 -scrapeMail -sender "$spammer" -nuke -username $username -password $password -socMailbox $socMailBox -LogRhythmHost $LogRhythmHost -caseAPItoken $caseAPItoken
                }
            }
        }
    }


    # Analyze reported phishing messages, and scrape any other unreported messages
    if ( $phishCount -gt 0 ) {
        
        # Set the initial Threat Score to 0 - increases as positive indicators for malware are observed during analysis
        $threatScore = 0
        
        # Track the user who reported the message
        $reportedBy = $reportPhish.Split(",")[2]; $reportedBy = $reportedBy.Split('"')[1]
        # Extract reported messages
        foreach($message in $messages){
            $msubject = $message.subject
            $mBody = $message.body

            $message.attachments|foreach {
                $attachment = $_.filename
                $a = $_.filename
                If (-Not ($a -match $boringFilesRegex)) {
                    $_.saveasfile((Join-Path $tmpFolder $a))
                }
            }

            $attachmentFull = $tmpFolder + $a

            $MoveTarget = $inbox.Folders.item("COMPLETED")
            [void]$message.Move($MoveTarget) 
        }

        $directoryInfo = Get-ChildItem $tmpFolder | findstr ".msg" | Measure-Object

        if ( $directoryInfo.count -gt 0 ) {
            
            $attachments = @(@(ls $tmpFolder).Name)
            
            if ($attachments -like "*.msg*") {
            
                foreach($attachment in $attachments) {

                    $msg = $outlook.Session.OpenSharedItem("$tmpFolder$attachment")

                    $subject = $msg.ConversationTopic
                    $messageBody = $msg.Body

                    $headers = $msg.PropertyAccessor.GetProperty("http://schemas.microsoft.com/mapi/proptag/0x007D001E")
                    $headers > "$tmpFolder\headers.txt"

                    $getLinks = $msg.Body | findstr -i http
                    $null > "$tmpFolder\links.txt"
                    
                    [Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
                    
                    foreach ($link in $getLinks) {
                        
                        $link = @(@($link.Split("<")[1])).Split(">")[0]
                            
                        if ($safeLinks -eq $true) {
                        
                            [string[]] $urlParts = $link.Split("?")[1]
                            [string[]] $linkParams = $urlParts.Split("&")

                            for ($n=0; $n -lt $linkParams.Length; $n++) {
                        
                                [string[]] $namVal = $linkParams[$n].Split("=")
                        
                                if($namVal[0] -eq "url") {
                        
                                    $encodedLink = $namVal[1]
                                    break
                                }
                            }
                            $link = [System.Web.HttpUtility]::UrlDecode($encodedLink)
                        }
                        $link >> "$tmpFolder\links.txt"
                    }
                    $links = type "$tmpFolder\links.txt" | Sort -Unique
                    $domains = (Get-Content $tmpFolder\links.txt) | %{ ([System.Uri]$_).Host } | Select-Object -Unique

                    $countLinks = @(@(Get-Content "$tmpFolder\links.txt" | Measure-Object -Line | Select-Object Lines | findstr -v "Lines -") -replace "`n|`r").Trim()
                    
                    $attachmentCount = $msg.Attachments.Count

                    if ( $attachmentCount -gt 0 ) {

                        # Define file hashing function
                        function Get-Hash(
                            [System.IO.FileInfo] $file = $(Throw 'Usage: Get-Hash [System.IO.FileInfo]'), 
                            [String] $hashType = 'sha256')
                        {
                          $stream = $null;  
                          [string] $result = $null;
                          $hashAlgorithm = [System.Security.Cryptography.HashAlgorithm]::Create($hashType )
                          $stream = $file.OpenRead();
                          $hashByteArray = $hashAlgorithm.ComputeHash($stream);
                          $stream.Close();

                          trap {
                            if ($stream -ne $null) { $stream.Close(); }
                            break;
                          }

                          # Convert the hash to Hex
                          $hashByteArray | foreach { $result += $_.ToString("X2") }
                          return $result
                        }
                        
                        # Get the filename and location
                        $attachedFileName = @(@($msg.Attachments | Select-Object Filename | findstr -v "FileName -") -replace "`n|`r").Trim() -replace '\s',''
                        $msg.attachments|foreach {
                            $phishingAttachment = $_.filename
                            If ($phishingAttachment -match $interestingFilesRegex) {
                                $_.saveasfile((Join-Path $tmpFolder + "\attachments\" + $phishingAttachment))

                                # Actions

                                # VirusTotal
                                if ( $virusTotal -eq $true ) {
                                    $VirusTotalResults = & $pieFolder\plugins\VirusTotal-PIE.ps1 -file "$tmpFolder\attachments\$phishingAttachment" -VTApiKey "$virusTotalAPI"
                                    
                                    $VirusTotalFlagged = $VirusTotalResults | findstr flagged

                                    $VirusTotalSHA256 = $VirusTotalResults | findstr SHA256
                                    $VirusTotalSHA256 = @($VirusTotalSHA256.Split("+")[1]).Trim()

                                    $VirusTotalLink = $VirusTotalResults | findstr Link
                                    $VirusTotalLink = @($VirusTotalLink.Split("+")[1]).Trim()
                                }
                            }
                        }
                    }

                    # Clean Up the SPAM
                    $MoveTarget = $inbox.Folders.item("SPAM")
                    [void]$msg.Move($MoveTarget)
                    $spammer = $msg.SenderEmailAddress
                    $spammerDisplayName = $msg.SenderName
                }
            }

        } else {
            
            $subject = $msubject
            if ($msubject.Contains("FW:") -eq $true) { $subject = @($msubject.Split(":")[1]).Trim() }
            if ($msubject.Contains("Fw:") -eq $true) { $subject = @($msubject.Split(":")[1]).Trim() }
            if ($msubject.Contains("fw:") -eq $true) { $subject = @($msubject.Split(":")[1]).Trim() }
            if ($msubject.Contains("FWD:") -eq $true) { $subject = @($msubject.Split(":")[1]).Trim() }
            if ($msubject.Contains("Fwd:") -eq $true) { $subject = @($msubject.Split(":")[1]).Trim() }
            if ($msubject.Contains("fwd:") -eq $true) { $subject = @($msubject.Split(":")[1]).Trim() }
            if ($msubject.Contains("RE:") -eq $true) { $subject = @($msubject.Split(":")[1]).Trim() }
            if ($msubject.Contains("Re:") -eq $true) { $subject = @($msubject.Split(":")[1]).Trim() }
            if ($msubject.Contains("re:") -eq $true) { $subject = @($msubject.Split(":")[1]).Trim() }

            
            $endUserName = $reportedBy.Split("@")[0]
            $endUserLastName = $endUserName.Split(".")[1]
            $subjectQuery = "Subject:" + "'" + $subject + "'" + " Sent:" + $day
            $subjectQuery = "'" + $subjectQuery + "'"
            $searchMailboxResults = Search-Mailbox $endUserName -SearchQuery $subjectQuery -TargetMailbox "$socMailbox" -TargetFolder "PROCESSING" -LogLevel Full

            <#
            $targetFolder = $searchMailboxResults.TargetFolder
            $outlookAnalysisFolder = @(@($rootFolders.Folders | ?{$_.Name -match "PROCESSING"}).Folders).FolderPath | findstr -i $endUserLastName

            #$MoveTarget = $inbox.Folders.item("SPAM")
            #[void]$msg.Move($MoveTarget)
            #$spammer = $msg.SenderEmailAddress
            #$spammerDisplayName = $msg.SenderName
            #>
            
            sleep 10 
            echo $null > $analysisLog
            $companyDomain = $socMailbox.Split("@")[1]
            Get-MessageTrace -RecipientAddress $reportedBy -StartDate $24Hours -EndDate $date | Select MessageTraceID,Received,*Address,*IP,Subject,Status,Size,MessageID | Export-Csv $tmpLog -NoTypeInformation
            $subject = $_.Split(",")[6]; $subject = $subject.Split('"')[1]
            type $tmpLog | ForEach-Object { $_ | Select-String -SimpleMatch $subject >> $analysisLog }
            (gc $analysisLog) | ? {$_.trim() -ne "" } | set-content $analysisLog
            $spammer = type $analysisLog | ForEach-Object { $_.Split(",")[2]  } | Sort | Get-Unique | findstr "@" | findstr -v "$companyDomain"
            $spammer = $spammer.Split('"')[1] | Sort | Get-Unique
        }

        # Pull more messages if the sender cannot be found (often happens when internal messages are reported)
        if (-Not $spammer.Contains("@") -eq $true) {
            
            sleep 10
            echo $null > $analysisLog
            $companyDomain = $socMailbox.Split("@")[1]
            Get-MessageTrace -RecipientAddress $reportedBy -StartDate $24Hours -EndDate $date | Select MessageTraceID,Received,*Address,*IP,Subject,Status,Size,MessageID | Export-Csv $tmpLog -NoTypeInformation
            $subject = $_.Split(",")[6]; $subject = $subject.Split('"')[1]
            type $tmpLog | ForEach-Object { $_ | Select-String -SimpleMatch $subject >> $analysisLog }
            (gc $analysisLog) | ? {$_.trim() -ne "" } | set-content $analysisLog
            <#          
            $spammer = type $analysisLog | ForEach-Object { $_.Split(",")[2]  } | Sort | Get-Unique | findstr "@" | findstr -v "$companyDomain"
            $spammer = $spammer.Split('"')[1] | Sort | Get-Unique
            #>

            $spammer = "Unknown"
        }
        
        # Create a case folder
        $caseID = Get-Date -Format M-d-yyyy_h-m-s
        if ( $spammer.Contains("@") -eq $true) {
            $spammerName = $spammer.Split("@")[0]
            $spammerDomain = $spammer.Split("@")[1]
            $caseID = echo $caseID"_Sender_"$spammerName".at."$spammerDomain
        } else {
            $caseID = echo $caseID"_Sent-as-Fwd"
        }
        mkdir $caseFolder$caseID

        # Check for Attachments
        if ($attachmentCount -gt 0) {
            mkdir "$caseFolder$caseID\attachments\"
            $msubject = $msg.subject 
            $mBody = $msg.body 

            $msg.attachments|foreach { 
                $attachment = $_.filename 
                $a = $_.filename 
                If (-Not ($a -match $boringFilesRegex)) { 
                    $_.saveasfile((Join-Path $tmpFolder $a)) 
                }
            }
            $attachmentFull = "$caseFolder$caseID\attachments\" + $a
            
            $files = $true

            # Make sure those files are moved
            cp "$tmpFolder\*.pdf" "$caseFolder$caseID\attachments\"
            cp "$tmpFolder\*.rar" "$caseFolder$caseID\attachments\"
            cp "$tmpFolder\*.tar" "$caseFolder$caseID\attachments\"
            cp "$tmpFolder\*.gz" "$caseFolder$caseID\attachments\"
            cp "$tmpFolder\*.xyz" "$caseFolder$caseID\attachments\"
            cp "$tmpFolder\*.zip" "$caseFolder$caseID\attachments\"
            cp "$tmpFolder\*.doc*" "$caseFolder$caseID\attachments\"
            cp "$tmpFolder\*.xls*" "$caseFolder$caseID\attachments\"
            cp "$tmpFolder\*.ppt*" "$caseFolder$caseID\attachments\"
            cp "$tmpFolder\*.dmg*" "$caseFolder$caseID\attachments\"
            cp "$tmpFolder\*.exe*" "$caseFolder$caseID\attachments\"
            cp "$tmpFolder\*.js" "$caseFolder$caseID\attachments\"
        }

        # Add evidence to the case folder
        cp $tmpFolder$attachment $caseFolder$caseID

        type "$tmpFolder\links.txt" | Sort -Unique > "$caseFolder$caseID\links.txt"
        type "$tmpFolder\headers.txt" > "$caseFolder$caseID\headers.txt"
        $msg.HTMLBody > "$caseFolder$caseID\email-source.txt"

        # Gather and count evidence
        if ( $spammer.Contains("@") -eq $true) {
            sleep 10
            Get-MessageTrace -SenderAddress $spammer -StartDate $48Hours -EndDate $date | Select MessageTraceID,Received,*Address,*IP,Subject,Status,Size,MessageID | Export-Csv $analysisLog -NoTypeInformation
        }
            $messageCount = type $analysisLog | findstr -v "MessageTraceId" | Measure-Object | Select-Object Count | findstr -v "Count -"
            $messageCount = $messageCount.Trim()
            $deliveredMessageCount = type $analysisLog | findstr "Delivered Resolved" | Measure-Object | Select-Object Count | findstr -v "Count -"
            $deliveredMessageCount = $deliveredMessageCount.Trim()
            $failedMessageCount = type $analysisLog | findstr "Failed" | Measure-Object | Select-Object Count | findstr -v "Count -"
            $failedMessageCount = $failedMessageCount.Trim()
            $recipients = Get-Content $analysisLog | ForEach-Object { $_.split(",")[3] }
            $recipients = $recipients -replace '"', "" | Sort | Get-Unique | findstr -v "RecipientAddress"
            $subjects = Get-Content $analysisLog | ForEach-Object { $_.split(",")[6] } | Sort | Get-Unique | findstr -v "Subject"
        
        # Build the Initial Summary
        $summary = @"
============================================================

Phishing Attack Reported by: $reportedBy
Reported on:                 $date
Spammer:                     $spammer
Spammer Name:                $spammerDisplayName
Subject:                     $subject
Messages Sent:              $messageCount
Messages Delivered:         $deliveredMessageCount
Case Folder:                 $caseID

============================================================
"@
        
        echo $banner > "$caseFolder$caseID\spam-report.txt"
        echo "" >> "$caseFolder$caseID\spam-report.txt"
        echo $summary >> "$caseFolder$caseID\spam-report.txt"
        echo "" >> "$caseFolder$caseID\spam-report.txt"
        echo "Unique Subject(s):" >> "$caseFolder$caseID\spam-report.txt"
        $subjects | ForEach-Object { echo "    $_"} >> "$caseFolder$caseID\spam-report.txt"
        echo "" >> "$caseFolder$caseID\spam-report.txt"
        echo "Recipient(s): " >> "$caseFolder$caseID\spam-report.txt"
        $recipients | ForEach-Object { echo "    $_"} >> "$caseFolder$caseID\spam-report.txt"
        $recipients | ForEach-Object { echo "$_"} >> "$caseFolder$caseID\recipients.txt"
        echo "" >> "$caseFolder$caseID\spam-report.txt"
        echo "============================================================" >> "$caseFolder$caseID\spam-report.txt"
        echo "" >> "$caseFolder$caseID\spam-report.txt"
        if ( $links ) {
            echo "Link(s):" >> "$caseFolder$caseID\spam-report.txt"
            echo "" >> "$caseFolder$caseID\spam-report.txt"
            type "$tmpFolder\links.txt" >> "$caseFolder$caseID\spam-report.txt"
            echo "" >> "$caseFolder$caseID\spam-report.txt"
            echo "============================================================" >> "$caseFolder$caseID\spam-report.txt"
            echo "" >> "$caseFolder$caseID\spam-report.txt"
        }
        echo "Message Body:" >> "$caseFolder$caseID\spam-report.txt"
        echo "" >> "$caseFolder$caseID\spam-report.txt"
        echo $messageBody >> "$caseFolder$caseID\spam-report.txt"
        echo "" >> "$caseFolder$caseID\spam-report.txt"
        echo "============================================================" >> "$caseFolder$caseID\spam-report.txt"
        echo "" >> "$caseFolder$caseID\spam-report.txt"
        echo "Message Headers:" >> "$caseFolder$caseID\spam-report.txt"
        echo "" >> "$caseFolder$caseID\spam-report.txt"
        echo $headers >> "$caseFolder$caseID\spam-report.txt"
        echo "" >> "$caseFolder$caseID\spam-report.txt"
        echo "============================================================" >> "$caseFolder$caseID\spam-report.txt"
        echo "" >> "$caseFolder$caseID\spam-report.txt"

        type $analysisLog >> "$caseFolder$caseID\message-trace-logs.csv"
        del "$tmpFolder\*"


# ================================================================================
# LOGRHYTHM CASE MANAGEMENT AND THIRD PARTY INTEGRATIONS
# ================================================================================

        if ( $spammer.Contains("@") -eq $true) {
            $caseSummary = "Phishing email from $spammer was reported on $date by $reportedBy. The subject of the email is ($subject). Initial analysis shows that $messageCount user(s) received this email in the past 48 hours."
            & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -createCase "Phishing : $spammerName [at] $spammerDomain" -priority 3 -summary "$caseSummary" -token $caseAPItoken
            sleep 5
        } else {
            $caseSummary = "Phishing email was reported on $date by $reportedBy. The subject of the email is ($subject). Initial analysis shows that $messageCount user(s) received this email in the past 48 hours."
            & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -createCase "Phishing Message Reported" -priority 3 -summary "$caseSummary" -token $caseAPItoken
        }
        $caseNumber = Get-Content "$pieFolder\plugins\case.txt"
        mv "$pieFolder\plugins\case.txt" "$caseFolder$caseID\"
        $caseURL = "https://$LogRhythmHost/cases/$caseNumber"

        # Tag the case as phishing
        if ( $defaultCaseTag ) {
            & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -addTag "$defaultCaseTag" -casenum $caseNumber -token $caseAPItoken
        }

        # Adding and assigning the Case Owner
        if ( $caseOwner ) {
            & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -addCaseUser "$caseOwner" -casenum $caseNumber -token $caseAPItoken
            sleep 1
            & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -changeCaseOwner "$caseOwner" -casenum $caseNumber -token $caseAPItoken
        }

        # Adding and assigning other users
        if ( $caseCollaborators ) {
            foreach ( $i in $caseCollaborators ) {
                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -addCaseUser "$i" -casenum $caseNumber -token $caseAPItoken
                sleep 1
            }
        }
        
        # Append Case Info to 
        echo "LogRhythm Case Information:" >> "$caseFolder$caseID\spam-report.txt"
        echo "" >> "$caseFolder$caseID\spam-report.txt"
        echo "Case #:      $caseNumber" >> "$caseFolder$caseID\spam-report.txt"
        echo "Case URL:    $caseURL" >> "$caseFolder$caseID\spam-report.txt"
        echo "" >> "$caseFolder$caseID\spam-report.txt"

        # Copy raw logs to case
        $caseNote = type $analysisLog
        $caseNote = $caseNote -replace '"', ""
        & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Raw Phishing Logs: $caseNote" -token $caseAPItoken
        
        # Recipients
        $messageRecipients = (Get-Content "$caseFolder$caseID\recipients.txt") -join ", "
        & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Email Recipients: $messageRecipients" -token $caseAPItoken


        # ================================================================================
        # Third Party Integrations
        # ================================================================================

        # WRIKE
        if ( $wrike -eq $true ) {

            $secOpsSummary = "Phishing email from $spammer was reported on $date by $reportedBy. The subject of the email is ($subject). Initial analysis shows that $messageCount user(s) received this email in the past 48 hours. For more information, review the LogRhythm Case and Evidence folder."           

            # Security Operations Contact(s)
            & $pieFolder\plugins\wrike.ps1 -newTask "Case $caseNumber - Phishing email from $spammer" -wrikeUserName $wrikeUser -wrikeFolderName $wrikeFolder -wrikeDescription $secOpsSummary -accessToken $wrikeAPI
            
            # Labs
            $labsSummary = "Phishing email from $spammer was reported on $date by $reportedBy. The subject of the email is ($subject). Initial analysis shows that $messageCount user(s) received this email in the past 48 hours. For more information, review the LogRhythm Case ($LogRhythmHost/cases/$caseNumber) and Evidence folder"
            & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Tasks Created in Wrike..." -token $caseAPItoken

        }

        # SCREENSHOT MACHINE
        if ( $screenshotMachine -eq $true ) {

            $links | ForEach-Object {
                $splitLink = ([System.Uri]"$_").Host

                Invoke-RestMethod "http://api.screenshotmachine.com/?key=$screenshotKey&dimension=1024x768&format=png&url=$_" -OutFile "$caseFolder$caseID\screenshot-$splitLink.png"
                    
                $screenshotStatus = "Screenshot of hxxp://$splitLink website has been captured and saved with the case folder: screenshot-$splitLink.png"
                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$screenshotStatus" -token $caseAPItoken
            }
        }

        # GET LINK INFO
        if ( $getLinkInfo -eq $true ) {
            
            $links | ForEach-Object { 
                $splitLink = $_.Split(":") | findstr -v http

                $linkInfo = iwr http://www.getlinkinfo.com/info?link=$_

                $linkInfo.RawContent | Out-File $tmpFolder\linkInfo.txt
                $isItSafe = Get-Content $tmpFolder\linkInfo.txt | Select-String -Pattern '((?![0]).) unsafe\)*'

                if ( $isItSafe ) {
                    $getLinkInfoStatus = "UNSAFE LINK DETECTED (hxxp:$splitLink)! More Information: http://www.getlinkinfo.com/info?link=$_"
                    $threatScore += 1
                } else {
                    $getLinkInfoStatus = "Link (hxxp:$splitLink) is considered low risk. More Information: http://www.getlinkinfo.com/info?link=$_"
                }

                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$getLinkInfoStatus" -token $caseAPItoken

                echo "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                echo "" >> "$caseFolder$caseID\spam-report.txt"
                echo "Get Link Info Status:" >> "$caseFolder$caseID\spam-report.txt"
                echo "" >> "$caseFolder$caseID\spam-report.txt"
                echo $getLinkInfoStatus >> "$caseFolder$caseID\spam-report.txt"
                echo "" >> "$caseFolder$caseID\spam-report.txt"

                Remove-Item -Path $tmpFolder\linkInfo.txt
            }
        }

        # PHISHTANK
        if ( $phishTank -eq $true ) {

            $links | ForEach-Object { 
                $splitLink = $_.Split(":") | findstr -v http

                if ( $phishTankAPI ) {
                    $postParams = @{url="$_";format="xml";app_key="$phishTankAPI"}
                } else {
                    $postParams = @{url="$_";format="xml"}
                }

                $phishTankResponse = iwr -Uri http://checkurl.phishtank.com/checkurl/ -Method POST -Body $postParams
                $phishTankStatus = @($phishTankResponse.Content | findstr in_database).Split(">")[1]
                $phishTankStatus = $phishTankStatus.Split("<")[0]

                $phishTankDetails = @($phishTankResponse.Content | findstr phish_detail_page).Split(">")[1]
                $phishTankDetails = $phishTankDetails.Split("\[")[2]
                $phishTankDetails = $phishTankDetails.Split("]")[0]

                if ( $phishTankStatus -eq "false" ) {
                    $phishTankStatus = "Link (hxxp:$splitLink) is not present in the PhishTank Database."
                } elseif ( $phishTankStatus -eq "true" ) {
                    $phishTankStatus = "MALICIOUS LINK (hxxp:$splitLink) was found in the PhishTank Database! More Information: $phishTankDetails"
                    $threatScore += 1
                }

                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$phishTankStatus" -token $caseAPItoken
                
                echo "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                echo "" >> "$caseFolder$caseID\spam-report.txt"
                echo "PhishTank Status:" >> "$caseFolder$caseID\spam-report.txt"
                echo "" >> "$caseFolder$caseID\spam-report.txt"
                echo $phishTankStatus >> "$caseFolder$caseID\spam-report.txt"
                echo "" >> "$caseFolder$caseID\spam-report.txt"
            }
        }

        # SUCURI LINK ANALYSIS
        if ( $sucuri -eq $true ) {

            $domains | ForEach-Object {
                $sucuriLink = "https://sitecheck.sucuri.net/results/$_"
                $sucuriAnalysis = iwr "https://sitecheck.sucuri.net/api/v2/?scan=$_&json"
                $sucuriAnalysis.RawContent | Out-File $tmpFolder\sucuriAnalysis.txt

                $sucuriResults = Get-Content $tmpFolder\sucuriAnalysis.txt | select -Skip 12 | ConvertFrom-Json
                $isitblacklisted = $sucuriResults.MALWARE.NOTIFICATIONS | Select-Object -Property 'Blacklist'
                $isitcompromised = $sucuriResults.MALWARE.NOTIFICATIONS | Select-Object -Property 'Websitemalware'

                if ( $isitblacklisted.BLACKLIST -eq $true ) {
                
                    $sucuriStatus = "MALICIOUS LINK! Sucuri has flagged this host: $splitLink. Full details available here: $sucuriLink."
                    $threatScore += 1

                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$sucuriStatus" -token $caseAPItoken
                
                } 
                
                if ( $isitcompromised.WEBSITEMALWARE -eq $true ) {
                
                    $sucuriStatus = "MALWARE DETECTED! Sucuri has flagged this host: $splitLink. Full details available here: $sucuriLink."
                    $threatScore += 1
                
                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$sucuriStatus" -token $caseAPItoken

                }
                if ( !$isitcompromised.BLACKLIST -eq $true -and !$isitcompromised.WEBSITEMALWARE -eq $true ) {
                    $sucuriStatus = "Sucuri has determined this link is clean.  Full details available here: $sucuriLink."

                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$sucuriStatus" -token $caseAPItoken

                }

                echo "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                echo "" >> "$caseFolder$caseID\spam-report.txt"
                echo "Sucuri Status:" >> "$caseFolder$caseID\spam-report.txt"
                echo "" >> "$caseFolder$caseID\spam-report.txt"
                echo $sucuriStatus >> "$caseFolder$caseID\spam-report.txt"
                echo "" >> "$caseFolder$caseID\spam-report.txt"

                Remove-Item -Path $tmpFolder\sucuriAnalysis.txt
            }
        }

        # DOMAIN TOOLS
        if ( $domainTools -eq $true ) {

            $domainIgnoreList = "bit.ly","ow.ly","x.co","goo.gl","logrhythm.com","google.com"
            $threshold = (Get-Date).AddMonths(-3)
            $threshold = $threshold.ToString("yyy-MM-dd")

            $links | ForEach-Object {
                If([string]$_ -match ($domainIgnoreList -join "|")) {
                    Write-Output "Nothing to analyze"
                } else {

                    $domain = @(([System.Uri]"$_").Host).Split(".")[-2]
                    $dn = @(([System.Uri]"$_").Host).Split(".")[-1]
                    $domain = "$domain.$dn"

                    try {
                        $domainDetails = Invoke-RestMethod "http://api.domaintools.com/v1/$domain/?api_username=$DTapiUsername&api_key=$DTapiKey"
                    } catch {
                        Write-Error "fail..."
                    }

                    $createdDate = $domainDetails.response.registration.created
                    $updatedDate = $domainDetails.response.registration.updated

                    $events = $domainDetails.response.history.registrar.events

                    if ( $createdDate ) {

                        if($threshold -le $createdDate){
                            $domainToolsUpdate = "DomainTools: Domain ($domain) is less than 3-months old - likely malicious! Registered on $createdDate. Threat Score Elevated."
                            $threatScore += 1
                        }else{
                            $domainToolsUpdate = "DomainTools: Domain ($domain) has been registered since $createdDate - low risk"
                        }

                    } else {

                        $registrationTime = $domainDetails.response.history.registrar.earliest_event

                        if($threshold -le $registrationTime){
                            $domainToolsUpdate = "DomainTools: Domain is less than 3-months old - likely malicious! Registered on $registrationTime. Threat Score Elevated."
                            $threatScore += 1
                        }else{
                            $domainToolsUpdate = "DomainTools: Domain has been registered since $registrationTime - low risk"
                        }
                    }
                }
                
                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$domainToolsUpdate" -token $caseAPItoken

                echo "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                echo "" >> "$caseFolder$caseID\spam-report.txt"
                echo "Domain Tools Status:" >> "$caseFolder$caseID\spam-report.txt"
                echo "" >> "$caseFolder$caseID\spam-report.txt"
                echo $domainToolsUpdate >> "$caseFolder$caseID\spam-report.txt"
                echo "" >> "$caseFolder$caseID\spam-report.txt"
            }
        }

        # SHODAN
        if ( $shodan -eq $true ) {

            echo "Shodan.io" >> "$caseFolder$caseID\spam-report.txt"
            echo "============================================================" >> "$caseFolder$caseID\spam-report.txt"

            $domains | ForEach-Object {
                echo "Shodan Analysis: $_" >> "$caseFolder$caseID\spam-report.txt"

                & $pieFolder\plugins\Shodan.ps1 -key $shodanAPI -link $_ -caseID $caseID -caseFolder "$caseFolder" -pieFolder "$pieFolder" -logRhythmHost $logRhythmHost -caseAPItoken $caseAPItoken
            
            }

            echo "============================================================" >> "$caseFolder$caseID\spam-report.txt"
            echo "" >> "$caseFolder$caseID\spam-report.txt"
        }

        # OPEN DNS
        if ( $openDNS -eq $true ) {

            $links | ForEach-Object {

                $splitLink = ([System.Uri]"$_").Host

                $OpenDNSurl = "https://investigate.api.umbrella.com/domains/categorization/$splitLink`?showLabels"
                $result = Invoke-RestMethod -Headers @{'Authorization' = "Bearer $openDNSkey"} -Uri $OpenDNSurl | ConvertTo-Json -Depth 4
                $newresult = $result | ConvertFrom-Json
                $score = $newresult.$splitLink.status

                if ($score -eq -1){
                    $OpenDNSStatus = "MALICIOUS DOMAIN - OpenDNS analysis determined $splitLink to be unsafe!"
                    $threatScore += 1
                }elseif ($score -eq 0) {
                    $OpenDNSStatus = "OpenDNS - Uncategorized Domain: $splitLink"
                } elseif ($score -eq 1) {
                    $OpenDNSStatus = "OpenDNS - Benign Domain: $splitLink"
                }

                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$OpenDNSStatus" -token $caseAPItoken

                echo "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                echo "" >> "$caseFolder$caseID\spam-report.txt"
                echo "OpenDNS Status:" >> "$caseFolder$caseID\spam-report.txt"
                echo "" >> "$caseFolder$caseID\spam-report.txt"
                echo $OpenDNSStatus >> "$caseFolder$caseID\spam-report.txt"
                echo "" >> "$caseFolder$caseID\spam-report.txt"
            }
        }

        # URL VOID
        if ( $urlVoid -eq $true ) {
            
            $links | ForEach-Object {
                
                $splitLink = ([System.Uri]"$_").Host
                    
                $urlVoidResponse = Invoke-RestMethod http://api.urlvoid.com/$urlVoidIdentifier/$urlVoidKey/host/$splitLink/
                $urlVoidCheckResponse = $urlVoidResponse.response.details.ip.addr
                $urlVoidError = $urlVoidResponse.response.error

                if ( $urlVoidError ) {
                    $urlVoidStatus = "URL VOID Error: API Key is Invalid"
                } else {

                    if ( $urlVoidCheckResponse ) {

                        $checkDetection = $urlVoidResponse.response.detections

                        if ( $checkDetection ) {

                            $urlVoidEngines = $urlVoidResponse.response.detections.engines.engine
                            $urlVoidCount = $urlVoidResponse.response.detections.count

                            $urlVoidStatus = "URL VOID: MALWARE DETECTED on (hxxp://$splitLink)! Detection Count: $urlVoidCount. Engines: $urlVoidEngines"
                            $threatScore += [int]$urlVoidCount

                        } else {

                            $urlVoidStatus = "URL VOID: Safe link detected (hxxp://$splitLink)"
                        }

                        $urlVoidIPdetails = $urlVoidResponse.response.details.ip

                    } else {

                        $urlVoidResponse = Invoke-RestMethod http://api.urlvoid.com/$urlVoidIdentifier/$urlVoidKey/host/$splitLink/scan/

                        if ( $urlVoidResponse.response.action_result -eq "OK" ) {

                            $checkDetection = $urlVoidResponse.response.detections

                            if ( $checkDetection ) {

                                $urlVoidEngines = $urlVoidResponse.response.detections.engines.engine
                                $urlVoidCount = $urlVoidResponse.response.detections.count

                                $urlVoidStatus = "URL VOID: New Scan - MALWARE DETECTED on (hxxp://$splitLink)! Detection Count: $urlVoidCount. Engines: $urlVoidEngines"
                                $threatScore += [int]$urlVoidCount

                            } else {

                                $urlVoidStatus = "URL VOID: New scan - Safe link detected (hxxp://$splitLink)"
                            }

                            $urlVoidIPdetails = $urlVoidResponse.response.details.ip

                        }

                    }    
                }
                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$urlVoidStatus" -token $caseAPItoken

                echo "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                echo "" >> "$caseFolder$caseID\spam-report.txt"
                echo "URL Void Domain Information (hxxp://$splitLink):" >> "$caseFolder$caseID\spam-report.txt"
                echo "" >> "$caseFolder$caseID\spam-report.txt"
                echo $urlVoidIPdetails >> "$caseFolder$caseID\spam-report.txt"
                echo "" >> "$caseFolder$caseID\spam-report.txt"
            }
        }

        # VIRUS TOTAL
        if ( $virusTotal -eq $true ) {

            if ( $virusTotalAPI ) {
            
                $links | ForEach-Object {
                    $splitLink = $_.Split(":") | findstr -v http

                    $postParams = @{apikey="$virusTotalAPI";resource="$_";}
                    $VTResponse = iwr http://www.virustotal.com/vtapi/v2/url/report -Method POST -Body $postParams

                    $VTResponse = $VTResponse.Content | ConvertFrom-Json

                    $VTLink = @($VTResponse | findstr permalink).Split(":")[2]
                    $VTLink = "https:$VTLink"

                    $VTPositives = @(@($VTResponse | findstr positives).Split(":")[1]).Trim()
                    $VTPositives = [int]$VTPositives

                    if ( $VTPositives -lt 1 ) {
                        $VTStatus = "VirusTotal has not flagged this link (hxxp:$splitLink) as malicious."
                    
                    } elseif ( $VTPositives -gt 0 ) {
                        $VTStatus = "MALICIOUS LINK DETECTED by VirusTotal (hxxp:$splitLink)! This sample has been flagged by $VTPositives Anti Virus engines. More information: $VTLink"
                        $threatScore += $VTPositives
                    }

                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$VTStatus" -token $caseAPItoken

                    echo "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                    echo "" >> "$caseFolder$caseID\spam-report.txt"
                    echo "VirusTotal Analysis Results:" >> "$caseFolder$caseID\spam-report.txt"
                    echo "" >> "$caseFolder$caseID\spam-report.txt"
                    echo $VTStatus >> "$caseFolder$caseID\spam-report.txt"
                    echo "" >> "$caseFolder$caseID\spam-report.txt"

                }
            } else { 
                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "VirusTotal API key required to check / submit samples" -token $caseAPItoken
            }
        }

        # SHORT LINK ANALYSIS
        if ( $shortLink -eq $true ) {
            
            $links | ForEach-Object {

                if ( $_ -match "https://bit.ly" ) {
                
                    # bit.ly
                    $shortLinkContent = iwr "$_+"
                    $expandedLink = ($shortLinkContent.Content | findstr -i long_url).Split('"') | findstr -i "http https" | unique

                    $splitLink = $expandedLink.Split(":") | findstr -v http

                    $shortLinkStatus = "Shortened Link Detected! Metrics: $_+. Redirect: hxxp:$splitLink"

                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$shortLinkStatus" -token $caseAPItoken
                }

                if ( $_ -match "https://goo.gl" ) {
                
                    # goo.gl
                    $shortLinkContent = iwr "$_+"
                    $expandedLink = ($shortLinkContent.Content | findstr -i long_url).Split('"') | findstr -i "http https" | unique
                    $splitLink = $expandedLink.Split(":") | findstr -v http

                    $shortLinkStatus = "Shortened Link Detected! Metrics: $_+."

                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$shortLinkStatus" -token $caseAPItoken
                }

                if ( $_ -match "http://x.co" ) {

                    # x.co
                    $splitLink = $_.Split(":") | findstr -v http
                    $shortLinkStatus = "Machine Learning analysis has detected a possibly malicious link hxxp:$_."
                    $threatScore += 1

                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$shortLinkStatus" -token $caseAPItoken
                }
            }
        }

        # Link RegEx Check
        if ( $linkRegexCheck ) {

            $linkRegexList = '/wp-admin/',
                                '/wp-includes/',
                                '/wp-content/(?!\S{0,60}Campaign\S{0,2}\=)(?!\S{0,60}\.pdf[<\"\t\r\n])(?!\S{0,60}\.jpg[<"\t\r\n])',
                                'blocked\ your?\ online',
                                'suspicious\ activit',
                                'updated?\ your\ account\ record',
                                'Securely\ \S{3,4}\ one(\ )?drive',
                                'Securely\ \S{3,4}\ drop(\ )?box',
                                'Securely\ \S{3,4}\ Google\ Drive',
                                'sign\ in\S{0,7}(with\ )?\ your\ email\ address',
                                'Verify\ your\ ID\s',
                                'dear\ \w{3,8}(\ banking)?\ user',
                                'chase\S{0,10}\.html"',
                                '\b(?<=https?://)(www\.)?icloud(?!\.com)',
                                '(?<![\x00\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5A])appie\W',
                                '/GoogleDrive/',
                                '/googledocs?/',
                                '/Dropfile/',
                                'limit\ (and\ suspend\ )?your\ account',
                                '\b(?<=https?://)(?!www\.paypal\.com/)\S{0,40}pa?y\S{0,2}al(?!\S*\.com/)',
                                'sitey\.me',
                                'myfreesites\.net',
                                '/uploadfile/',
                                '/\S{0,3}outloo\S{0,2}k\S{1,3}\W',
                                '\b(?<=https?://webmail\.)\S{0,40}webmail\w{0,3}(?!/[0-9])(?!\S{0,40}\.com/)',
                                'owaportal',
                                'outlook\W365',
                                '/office\S{0,3}365/',
                                '-icloud\Wcom',
                                'pyapal',
                                '/docu\S{0,3}sign\S{1,4}/',
                                '/helpdesk/',
                                'pay\Sa\S{0,2}login',
                                '/natwest/',
                                '/dro?pbo?x/',
                                '%20paypal',
                                '\.invoice\.php',
                                'security-?err',
                                '/newdropbox/',
                                '/www/amazon',
                                'simplefileupload',
                                'security-?warning',
                                '-(un)?b?locked',
                                '//helpdesk(?!\.)',
                                '\.my-free\.website',
                                'mail-?update',
                                '\.yolasite\.com',
                                '//webmail(?!\.)',
                                '\.freetemplate\.site',
                                '\.sitey\.me',
                                '\.ezweb123\.com',
                                '\.tripod\.com',
                                '\.myfreesites\.net',
                                'mailowa',
                                '-icloud',
                                'icloud-',
                                'contabo\.net',
                                '\.xyz/',
                                'ownership\ validation\ (has\ )?expired',
                                'icloudcom',
                                '\w\.jar(?=\b)',
                                '/https?/www/',
                                '\.000webhost(app)?\.com',
                                'is\.gd/',
                                '\.weebly\.com',
                                '\.wix\.com',
                                'tiny\.cc/',
                                '\.joburg',
                                '\.top/'
            
            $links | ForEach-Object { 
                $splitLink = $_.Split(":") | findstr -v http

                If([string]$_ -match ($linkRegexList -join "|")) {
                    $regExCheckStatus = "UNSAFE LINK DETECTED (hxxp:$splitLink)! Positive RegEx match - possibly malicious."
                    $threatScore += 1
                } else {
                    Write-Host "No RegEx matches for (hxxp:$splitLink) - potentially benign."
                }

                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$regExCheckStatus" -token $caseAPItoken

                echo "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                echo "" >> "$caseFolder$caseID\spam-report.txt"
                echo "RegEx Check Status:" >> "$caseFolder$caseID\spam-report.txt"
                echo "" >> "$caseFolder$caseID\spam-report.txt"
                echo $regExCheckStatus >> "$caseFolder$caseID\spam-report.txt"
                echo "" >> "$caseFolder$caseID\spam-report.txt"
            }
        }

        # THREAT GRID
        if ( $threatGrid -eq $true ) {

            if ( $files ) {
                # Update Case
                $caseNote = "The collected files are now being analyzed for risk using Cisco AMP Threat Grid..."
                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$caseNote" -token $caseAPItoken
                
                $allAttachments = ls "$tmpFolder\attachments\"
                $allAttachments.Name | ForEach-Object { 
                    & $pieFolder\plugins\ThreatGRID-PIE.ps1 -file "$tmpFolder\attachments\$_" -key $threatGridAPI -caseNumber $caseNumber -caseFolder "$caseFolder$caseID" -caseAPItoken $caseAPItoken -LogRhythmHost $LogRhythmHost
                }
            
            } elseif ( $countLinks -gt 0 ) {
                # Update Case
                $caseNote = "The collected links are now being analyzed for risk using Cisco AMP Threat Grid..."
                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$caseNote" -token $caseAPItoken

                $links | ForEach-Object { 
                    & $pieFolder\plugins\ThreatGRID-PIE.ps1 -url "$_" -key $threatGridAPI -caseNumber $caseNumber -caseFolder "$caseFolder$caseID" -caseAPItoken $caseAPItoken -LogRhythmHost $LogRhythmHost
                }
            } else {
                # Nothing to do
                $caseNote = "No content for Cisco AMP Threat Grid to analyze..."
                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$caseNote" -token $caseAPItoken
            }

            #$threatGridScore = "90"
            #$threatGridRisk = "HIGH RISK"
            #& $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "ThreatGRID Analysis Score: $threatGridScore ($threatGridRisk)" -token $caseAPItoken
        }

        
        # ADD SPAMMER TO LIST
        if ( $spammerList ) {
            if ( $threatScore -gt $threatThreshold ) {
                if ( $spammer.Contains("@") -eq $true) {
                    
                    & $pieFolder\plugins\List-API.ps1 -lrhost $LogRhythmHost -appendToList "$spammer" -listName "$spammerList" -token $caseAPItoken
                    sleep 1
                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Spammer ($spammer) added to Threat List ($spammerList)" -token $caseAPItoken
                
                } else {
                
                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Unable to extract the spammer's email - manual analysis of the message is required" -token $caseAPItoken
                
                }
            }
        }

        
        # AUTO QUARANTINE ACTIONS
        if ( $autoQuarantine -eq $true ) {

            if ( $threatScore -gt $threatThreshold ) {
                $autoQuarantineNote = "Initiating auto-quarantine based on Threat Score of $threatScore. Copying messages to the Phishing inbox and hard-deleting from all recipient inboxes."
                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$autoQuarantineNote" -token $caseAPItoken
                sleep 5
                if ( $EncodedXMLCredentials ) {
                    & $pieFolder\plugins\O365Ninja.ps1 -scrapeMail -sender "$spammer" -nuke -caseNumber $caseNumber -encodedXMLCredentials "$EncodedXMLCredentials" -socMailbox $socMailBox -LogRhythmHost $LogRhythmHost -caseAPItoken $caseAPItoken
                } else {
                    & $pieFolder\plugins\O365Ninja.ps1 -scrapeMail -sender "$spammer" -nuke -caseNumber $caseNumber -username $username -password $password -socMailbox $socMailBox -LogRhythmHost $LogRhythmHost -caseAPItoken $caseAPItoken
                }
            }

            if ( $threatScore -lt $threatThreshold ) {
                $autoQuarantineNote = "Email not quarantined due to a required Threat Threshold of $threatThreshold."
                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$autoQuarantineNote" -token $caseAPItoken
            }

            echo "============================================================" >> "$caseFolder$caseID\spam-report.txt"
            echo "" >> "$caseFolder$caseID\spam-report.txt"
            echo "Message Auto Quarantine Status:" >> "$caseFolder$caseID\spam-report.txt"
            echo "" >> "$caseFolder$caseID\spam-report.txt"
            echo $autoQuarantineNote >> "$caseFolder$caseID\spam-report.txt"
            echo "" >> "$caseFolder$caseID\spam-report.txt"
        }

        if ( $autoBan -eq $true ) {

            if ( $threatScore -gt $threatThreshold ) {
                $autoBanNote = "Automatically banning $spammer based on Threat Score of $threatScore."
                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$autoBanNote" -token $caseAPItoken
                sleep 5
                if ( $EncodedXMLCredentials ) {
                    & $pieFolder\plugins\O365Ninja.ps1 -blockSender -sender "$spammer" -caseNumber $caseNumber -encodedXMLCredentials "$EncodedXMLCredentials" -socMailbox $socMailBox -LogRhythmHost $LogRhythmHost -caseAPItoken $caseAPItoken
                } else {
                    & $pieFolder\plugins\O365Ninja.ps1 -blockSender -sender "$spammer" -caseNumber $caseNumber -username $username -password $password -socMailbox $socMailBox -LogRhythmHost $LogRhythmHost -caseAPItoken $caseAPItoken
                }
            }

            if ( $threatScore -lt $threatThreshold ) {
                $autoBanNote = "Sender ($spammer) not quarantined due to a required Threat Threshold of $threatThreshold."
                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$autoBanNote" -token $caseAPItoken
            }

            echo "============================================================" >> "$caseFolder$caseID\spam-report.txt"
            echo "" >> "$caseFolder$caseID\spam-report.txt"
            echo "Message Auto Ban Status:" >> "$caseFolder$caseID\spam-report.txt"
            echo "" >> "$caseFolder$caseID\spam-report.txt"
            echo $autobanNote >> "$caseFolder$caseID\spam-report.txt"
            echo "" >> "$caseFolder$caseID\spam-report.txt"
        }

        # ================================================================================
        # Case Closeout
        # ================================================================================

        # Final Threat Score
        & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Email Threat Score: $threatScore" -token $caseAPItoken

        echo "============================================================" >> "$caseFolder$caseID\spam-report.txt"
        echo "" >> "$caseFolder$caseID\spam-report.txt"
        echo "Email Threat Score: $threatScore" >> "$caseFolder$caseID\spam-report.txt"
        echo "" >> "$caseFolder$caseID\spam-report.txt"
        echo "============================================================" >> "$caseFolder$caseID\spam-report.txt"
        echo "" >> "$caseFolder$caseID\spam-report.txt"

        # Add Network Share Location to the Case
        $hostname = hostname
        $networkShare = "\\\\$hostname\\cases\\$caseID\\"
        & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Case Details: $networkShare" -token $caseAPItoken
        
        }
}


# ================================================================================
# LOG ROTATION
# ================================================================================

# Log rotation script stolen from:
#      https://gallery.technet.microsoft.com/scriptcenter/PowerShell-Script-to-Roll-a96ec7d4

function Reset-Log 
{ 
    #function checks to see if file in question is larger than the paramater specified if it is it will roll a log and delete the oldes log if there are more than x logs. 
    param([string]$fileName, [int64]$filesize = 1mb , [int] $logcount = 5) 
     
    $logRollStatus = $true 
    if(test-path $filename) 
    { 
        $file = Get-ChildItem $filename 
        if((($file).length) -ige $filesize) #this starts the log roll 
        { 
            $fileDir = $file.Directory 
            $fn = $file.name #this gets the name of the file we started with 
            $files = Get-ChildItem $filedir | ?{$_.name -like "$fn*"} | Sort-Object lastwritetime 
            $filefullname = $file.fullname #this gets the fullname of the file we started with 
            #$logcount +=1 #add one to the count as the base file is one more than the count 
            for ($i = ($files.count); $i -gt 0; $i--) 
            {  
                #[int]$fileNumber = ($f).name.Trim($file.name) #gets the current number of the file we are on 
                $files = Get-ChildItem $filedir | ?{$_.name -like "$fn*"} | Sort-Object lastwritetime 
                $operatingFile = $files | ?{($_.name).trim($fn) -eq $i} 
                if ($operatingfile) 
                 {$operatingFilenumber = ($files | ?{($_.name).trim($fn) -eq $i}).name.trim($fn)} 
                else 
                {$operatingFilenumber = $null} 
 
                if(($operatingFilenumber -eq $null) -and ($i -ne 1) -and ($i -lt $logcount)) 
                { 
                    $operatingFilenumber = $i 
                    $newfilename = "$filefullname.$operatingFilenumber" 
                    $operatingFile = $files | ?{($_.name).trim($fn) -eq ($i-1)} 
                    write-host "moving to $newfilename" 
                    move-item ($operatingFile.FullName) -Destination $newfilename -Force 
                } 
                elseif($i -ge $logcount) 
                { 
                    if($operatingFilenumber -eq $null) 
                    {  
                        $operatingFilenumber = $i - 1 
                        $operatingFile = $files | ?{($_.name).trim($fn) -eq $operatingFilenumber} 
                        
                    } 
                    write-host "deleting " ($operatingFile.FullName) 
                    remove-item ($operatingFile.FullName) -Force 
                } 
                elseif($i -eq 1) 
                { 
                    $operatingFilenumber = 1 
                    $newfilename = "$filefullname.$operatingFilenumber" 
                    write-host "moving to $newfilename" 
                    move-item $filefullname -Destination $newfilename -Force 
                } 
                else 
                { 
                    $operatingFilenumber = $i +1  
                    $newfilename = "$filefullname.$operatingFilenumber" 
                    $operatingFile = $files | ?{($_.name).trim($fn) -eq ($i-1)} 
                    write-host "moving to $newfilename" 
                    move-item ($operatingFile.FullName) -Destination $newfilename -Force    
                } 
                     
            } 
 
                     
          } 
         else 
         { $logRollStatus = $false} 
    } 
    else 
    { 
        $logrollStatus = $false 
    } 
    $LogRollStatus 
}
 
Reset-Log -fileName $traceLog -filesize 50mb -logcount 10
Reset-Log -fileName $phishLog -filesize 25mb -logcount 10
#Reset-Log -fileName $spamTraceLog -filesize 25mb -logcount 10

# Kill Office365 Session and Clear Variables
Remove-PSSession $Session
Get-Variable -Exclude Session,banner | Remove-Variable -EA 0
