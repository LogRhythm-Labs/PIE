
  #====================================#
  # PIE - Phishing Intelligence Engine #
  # LogRhythm Security Operations      #
  # v3.0  --  December 2018            #
  #====================================#

# Copyright 2018 LogRhythm Inc.   
# Licensed under the MIT License. See LICENSE file in the project root for full license information.

<#

INSTALL:

    Review lines 43 through 100
        Add credentials under each specified section - Office 365 Connectivity and LogRhythm Case API Integration
        Define the folder where you will deploy the Invoke-O365MessageTrace.ps1 script from

    Review Lines 90 through 169./
        For each setting that you would like to enable, change the value from $false to $true
        For each enabled third party plugin, set the API key and other required paramters

USAGE:

    Configure as a scheduled task to run every 15-minutes:
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
$ErrorActionPreference= 'continue'
$VerbosePreference= 'continue'

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

# Auto-auditing mailboxes. Set to $true if you'd like to automatically enable auditing on new O365 mailboxes
$autoAuditMailboxes = $false

# Case Tagging and User Assignment
$defaultCaseTag = "phishing" # Default value - modify to match your case tagging schema. If this value does not exist, the script will not add the parameter to the case.
$caseOwner = "" # Primary case owner / SOC lead
$caseCollaborators = ("lname1, fname1", "lname2, fname2") # Add as many users as you would like, separate them like so: "user1", "user2"...

# Auto-auditing mailboxes.  Set to $true if you'd like to automatically enable auditing on new O365 mailboxes
$autoAuditMailboxes = $false

# Set to true if internal e-mail addresses resolve to user@xxxx.onmicrosoft.com.  Typically true for test or lab 365 environments.
$onMicrosoft = $false

# Set your local organization's e-mail format
# 1 = firstname.lastname@example.com
# 2 = FLastname@example.com - First Initial of First Name, full Last Name
# 3 = FirstnameLastname@example.com
$orgEmailFormat = 2


# ================================================================================
# Third Party Analytics
# ================================================================================

# For each supported module, set the flag to $true and enter the associated API key

# Auto Quarantine or Auto Ban?
$autoQuarantine = $false # Auto quarantine and/or ban the sender
$subjectAutoQuarantine = $false # Auto quarantine and create a case if the email matches the subject line regex check
$autoBan = $false # Auto blacklist known-bad senders
$threatThreshold = 5 # Actions run when the threat score is greater than the 'threatThreshold' below

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

# URL Scan
$urlscan = $false
$urlscanAPI = ""
#Maximum number of URLs to submit
$urlscanMax = "5"

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

# Palo Alto Wildfire
$wildfire = $false
$wildfireAPI = ""

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

# Date Variables
$date = Get-Date
$oldAF = (Get-Date).AddDays(-10)
$96Hours = (Get-Date).AddHours(-96)
$48Hours = (Get-Date).AddHours(-48)
$24Hours = (Get-Date).AddHours(-24)
$inceptionDate = (Get-Date).AddMinutes(-16)
$phishDate = (Get-Date).AddMinutes(-31)
$day = Get-Date -Format MM-dd-yyyy

# Folder Structure
$traceLog = "$pieFolder\logs\ongoing-trace-log.csv"
$phishLog = "$pieFolder\logs\ongoing-phish-log.csv"
$spamTraceLog = "$pieFolder\logs\ongoing-outgoing-spam-log.csv"
$analysisLog = "$pieFolder\logs\analysis.csv"
$lastLogDateFile = "$pieFolder\logs\last-log-date.txt"
$tmpLog = "$pieFolder\logs\tmp.csv"
$caseFolder = "$pieFolder\cases\"
$tmpFolder = "$pieFolder\tmp\"
$confFolder = "$pieFolder\conf\"
$runLog = "$pieFolder\logs\pierun.txt"
$log = $true
try {
    $lastLogDate = [DateTime]::SpecifyKind((Get-Content -Path $lastLogDateFile),'Utc')
}
catch {
    $lastLogDate = $inceptionDate
}


#URL Whitelist
$urlWhitelist = type "$confFolder\urlWhitelist.txt" | Sort -Unique | foreach { $_ + '*' }
$domainWhitelist = (Get-Content $confFolder\urlWhitelist.txt) | %{ ([System.Uri]$_).Host } | Select-Object -Unique | foreach { $_ + '*' }



# Email Parsing Varibles
$boringFiles = @('jpg', 'png', 'ico', 'tif')    
$boringFilesRegex = [string]::Join('|', $boringFiles)
$interestingFiles = @('pdf', 'exe', 'zip', 'doc', 'docx', 'docm', 'xls', 'xlsx', 'xlsm', 'ppt', 'pptx', 'arj', 'jar', '7zip', 'tar', 'gz', 'html', 'js', 'rpm', 'bat', 'cmd')
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

# Timestamp Function
function Get-TimeStamp {
    return "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
}


# Link and Domain Verification
$IPregex=‘(?<Address>((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))’
[regex]$URLregex = '(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?'
[regex]$IMGregex =  '(http(s?):)([/|.|\w|\s|-])*\.(?:jpg|gif|png)'


#Create phishLog if file does not exist.
if ( $(Test-Path $runLog -PathType Leaf) -eq $false ) {
        Set-Content $runLog -Value "PIE Powershell Runlog for $date"
        Write-Output "$(Get-TimeStamp) INFO - No runLog detected.  Created new $runLog" | Out-File $runLog
}
Write-Output "$(Get-TimeStamp) STATUS - BEGIN NEW PIE EXECUTION" | Out-File $runLog -Append

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
        Write-Output "$(Get-TimeStamp) ERROR - Could not find credentials file: $CredentialsFile" | Out-File $runLog -Append
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
    Write-Output "$(Get-TimeStamp) INFO - Open Office 365 connection" | Out-File $runLog -Append
} Catch {
    Write-Error "Access Denied..."
    Write-Output "$(Get-TimeStamp) ERROR - Office 365 connection Access Denied" | Out-File $runLog -Append
    Break;
}


# ================================================================================
# MEAT OF THE PIE
# ================================================================================
Write-Output "$(Get-TimeStamp) INFO - Check for new reports " | Out-File $runLog -Append
if ( $log -eq $true) {
    if ( $autoAuditMailboxes -eq $true ) {
        Write-Output "$(Get-TimeStamp) INFO - Started Inbox Audit Update" | Out-File $runLog -Append
        # Check for mailboxes where auditing is not enabled and is limited to 1000 results
        $UnauditedMailboxes=(Get-Mailbox -Filter {AuditEnabled -eq $false}).Identity
        $UAMBCount=$UnauditedMailboxes.Count
        if ($UAMBCount -gt 0){
            Write-Host "Attempting to enable auditing on $UAMBCount mailboxes, please wait..." -ForegroundColor Cyan
            $UnauditedMailboxes | % { 
                Try {
                    $auditRecipient = Get-Recipient $_
                    Set-Mailbox -Identity $_ -AuditDelegate SendAs,SendOnBehalf,Create,Update,SoftDelete,HardDelete -AuditEnabled $true -ErrorAction Stop
                } Catch {
                    #Catch handles conflicts where multiple users share the same firstname, lastname.
                    Write-Host "Issue: $($PSItem.ToString())"
                    for ($i = 0 ; $i -lt $auditRecipient.Count ; $i++) {
                        Set-Mailbox -Identity $($auditRecipient[$i].guid.ToString()) -AuditDelegate SendAs,SendOnBehalf,Create,Update,SoftDelete,HardDelete -AuditEnabled $true
                    }
                }

            }
            Write-Host "Finished attempting to enable auditing on $UAMBCount mailboxes." -ForegroundColor Yellow
        }
        if ($UAMBCount -eq 0){} # Do nothing, all mailboxes have auditing enabled.
        Write-Output "$(Get-TimeStamp) INFO - Completed Inbox Audit Update" | Out-File $runLog -Append
    }

    #Create phishLog if file does not exist.
    if ( $(Test-Path $phishLog -PathType Leaf) -eq $false ) {
        Set-Content $phishLog -Value "MessageTraceId,Received,SenderAddress,RecipientAddress,FromIP,ToIP,Subject,Status,Size,MessageId"
        Write-Output "$(Get-TimeStamp) INFO - No phishlog detected.  Created new $phishLog" | Out-File $runLog -Append
    }
    
    # new scrape mail - by sslawter - LR Community
    Write-Output "$(Get-TimeStamp) STATUS - Begin processing messageTrace" | Out-File $runLog -Append
    foreach ($page in 1..1000) {
        $messageTrace = Get-MessageTrace -StartDate $lastlogDate -EndDate $date -Page $page | Select MessageTraceID,Received,*Address,*IP,Subject,Status,Size,MessageID
        if ($messageTrace.Count -ne 0) {
            $messageTraces += $messageTrace
            Write-Verbose "Page #: $page"
            Write-Output "$(Get-TimeStamp) INFO - Processing page $page" | Out-File $runLog -Append
        }
        else {
            break
        }
    }
    $messageTracesSorted = $messageTraces | Sort-Object Received
    $messageTracesSorted | Export-Csv $traceLog -NoTypeInformation -Append
    ($messageTracesSorted | Select-Object -Last 1).Received.GetDateTimeFormats("O") | Out-File -FilePath $lastLogDateFile -Force -NoNewline
    Write-Output "$(Get-TimeStamp) STATUS - Completed messageTrace" | Out-File $runLog -Append

    # Search for Reported Phishing Messages
    Write-Output "$(Get-TimeStamp) INFO - Loading previous reports to phishHistory" | Out-File $runLog -Append
    $phishHistory = Get-Content $phishLog | ConvertFrom-Csv -Header "MessageTraceID","Received","SenderAddress","RecipientAddress","FromIP","ToIP","Subject","Status","Size","MessageID"
    Write-Output "$(Get-TimeStamp) INFO - Loading current reports to phishTrace" | Out-File $runLog -Append
    $phishTrace = Get-MessageTrace -RecipientAddress $socMailbox -Status Delivered | Select MessageTraceID,Received,SenderAddress,RecipientAddress,FromIP,ToIP,Subject,Status,Size,MessageID | Sort-Object Received
    Write-Output "$(Get-TimeStamp) INFO - Writing phishTrace to $tmpLog" | Out-File $runLog -Append
    $phishTrace | Export-Csv $tmpLog -NoTypeInformation
    Write-Output "$(Get-TimeStamp) INFO - Comparing phishTrace to phishHistory" | Out-File $runLog -Append
    $phishNewReports = Get-Content $tmpLog | ConvertFrom-Csv -Header "MessageTraceID","Received","SenderAddress","RecipientAddress","FromIP","ToIP","Subject","Status","Size","MessageID"
    if ((get-item $tmpLog).Length -gt 0) {
        $newReports = Compare-Object $phishHistory $phishNewReports -Property MessageTraceID -PassThru -IncludeEqual | Where-Object {$_.SideIndicator -eq '=>' } | Select-Object MessageTraceID,Received,SenderAddress,RecipientAddress,FromIP,ToIP,Subject,Status,Size,MessageID
        Write-Verbose "L268 - newReports: $($newReports.SenderAddress)"
        Write-Output "$(Get-TimeStamp) DEBUG - newReports Sender Address: $($newReports.SenderAddress)" | Out-File $runLog -Append
    } 
    if ($newReports -eq $null) {
        Write-Host "No phishing e-mails reported."
        Write-Output "$(Get-TimeStamp) INFO - No new reports detected" | Out-File $runLog -Append
    }
    if ($newReports -ne $null) {
        Write-Output "$(Get-TimeStamp) INFO - New reports detected reported by $($newReports.RecipientAddress)" | Out-File $runLog -Append
        Write-Output "$(Get-TimeStamp) INFO - Connecting to local inbox" | Out-File $runLog -Append
        # Connect to local inbox #and check for new mail
        $outlookInbox = 6
        $outlook = new-object -com outlook.application
        $ns = $outlook.GetNameSpace("MAPI")
        $olSaveType = "Microsoft.Office.Interop.Outlook.OlSaveAsType" -as [type]
        $rootFolders = $ns.Folders | ?{$_.Name -match $env:phishing}
        $inbox = $ns.GetDefaultFolder($outlookInbox)
        Write-Output "$(Get-TimeStamp) INFO - Connection to local inbox complete" | Out-File $runLog -Append
        #$messages = $inbox.items
        #$phishCount = $messages.count

        #Enable support for .eml format
        #From https://gallery.technet.microsoft.com/office/Blukload-EML-files-to-e1b83f7f
        Function Load-EmlFile
        {
            Param
            (
                $EmlFileName
            )

            Begin{
                $EMLStream = New-Object -ComObject ADODB.Stream
                $EML = New-Object -ComObject CDO.Message
            }

            Process{
                Try{
                    $EMLStream.Open()
                    $EMLStream.LoadFromFIle($EmlFileName)
                    $EML.DataSource.OpenObject($EMLStream,"_Stream")
                }
                Catch
                {
                }
            }
            End{
                return $EML
            }
        }

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

        Write-Output "$(Get-TimeStamp) STATUS - Begin processing newReports" | Out-File $runLog -Append
        $newReports | ForEach-Object {
            #Add $newReport to $phishLog
            Write-Output "$(Get-TimeStamp) INFO - Adding new report to phishLog for recipient $($_.RecipientAddress)" | Out-File $runLog -Append
            echo "`"$($_.MessageTraceID)`",`"$($_.Received)`",`"$($_.SenderAddress)`",`"$($_.RecipientAddress)`",`"$($_.FromIP)`",`"$($_.ToIP)`",`"$($_.Subject)`",`"$($_.Status)`",`"$($_.Size)`",`"$($_.MessageID)`"" | Out-File $phishLog -Encoding utf8 -Append
            # Track the user who reported the message
            $reportedBy = $($_.SenderAddress)
            $reportedSubject = $($_.Subject)
            Write-Output "$(Get-TimeStamp) INFO - Sent By: $($_.SenderAddress)  reportedSubject: $reportedSubject" | Out-File $runLog -Append
            Write-Verbose "L348 - reportedBy: $reportedBy  reportedSubject: $reportedSubject"
            
            #Access local inbox and check for new mail
            $messages = $inbox.items
            $phishCount = $messages.count

            Write-Output "$(Get-TimeStamp) STATUS - Begin AutoQuarantine block" | Out-File $runLog -Append
            # AutoQuarantinebySubject
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
                #[string]
                If($reportedSubject -match ($subjectRegex -join "|")) {
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
            Write-Output "$(Get-TimeStamp) STATUS - End AutoQuarantine block" | Out-File $runLog -Append

            Write-Output "$(Get-TimeStamp) STATUS - Begin Phishing Analysis block" | Out-File $runLog -Append
            # Analyze reported phishing messages, and scrape any other unreported messages    
            if ( $phishCount -gt 0 ) {
                Write-Output "$(Get-TimeStamp) INFO - phishCount > 0" | Out-File $runLog -Append
                # Set the initial Threat Score to 0 - increases as positive indicators for malware are observed during analysis
                $threatScore = 0

                # Extract reported messages
                Write-Output "$(Get-TimeStamp) INFO - Parse Outlook messages" | Out-File $runLog -Append
                foreach($message in $messages){
                    Write-Verbose "L400 - Outlook Message Subject: $($message.Subject)"
                    #Match known translation issues
                    Write-Output "$(Get-TimeStamp) INFO - Filtering known bad characters for $($message.Subject)" | Out-File $runLog -Append
                    if ($($message.Subject) -like "*’*") { $message.Subject = $message.Subject.Replace("’", "?") } 
                    if ($($message.Subject) -like "*ðŸ¦*") { $message.Subject = $message.Subject.Replace("ðŸ¦", "????") }
                    if ($($message.Subject) -like "*❯*") { $message.Subject = $message.Subject.Replace("❯", "?") }
                    if ($($message.Subject) -like "*🎄*") { $message.Subject = $message.Subject.Replace("🎄", "?") }
                    if ($($message.Subject) -like "*™*") { $message.Subject = $message.Subject.Replace("™", "?") }
                    if ($($message.Subject) -like "*🎁*") { $message.Subject = $message.Subject.Replace("🎁", "??") }


                    Write-Output "$(Get-TimeStamp) DEBUG - Post filter reportedSubject: $reportedSubject" | Out-File $runLog -Append
                    Write-Output "$(Get-TimeStamp) DEBUG - Post filter Outlook Subject: $($message.Subject)" | Out-File $runLog -Append
                    if ($($message.Subject) -eq $reportedSubject) {
                        Write-Output "$(Get-TimeStamp) INFO - Outlook message.subject matched reported message Subject" | Out-File $runLog -Append
                        $msubject = $message.subject
                        $mBody = $message.body
                        Write-Output "$(Get-TimeStamp) INFO - Parsing attachments" | Out-File $runLog -Append
                        $message.attachments|foreach {
                            Write-Verbose "File name: $($_.filename)"
                            Write-Output "$(Get-TimeStamp) INFO - File $($_.filename)" | Out-File $runLog -Append
                            $attachment = $_.filename
                            $attachmentFull = $tmpFolder+$attachment
                            If (-Not ($a -match $boringFilesRegex)) {
                                $_.SaveAsFile((Join-Path $tmpFolder $attachment))
                                if ($attachment -NotLike "*.msg*" -and $attachment -NotLike "*.eml*" -and $attachment -NotLike "*.jpg" -and $attachment -NotLike "*.png" -and $attachment -NotLike "*.tif") {
                                    sleep 1
                                    $fileHashes += @(Get-FileHash -Path "$attachmentFull" -Algorithm SHA256)
                                    Write-Verbose "L414 Interesting File Path for Hashes: $attachmentFull"
                                }
                            }
                        }
                        Write-Output "$(Get-TimeStamp) INFO - Moving Outlook message to COMPLETED folder " | Out-File $runLog -Append
                        $MoveTarget = $inbox.Folders.item("COMPLETED")
                        [void]$message.Move($MoveTarget) 
                    }
                    
                }
                Write-Output "$(Get-TimeStamp) INFO - Setting directoryInfo " | Out-File $runLog -Append
                $directoryInfo = Get-ChildItem $tmpFolder | findstr "\.msg \.eml" | Measure-Object
            
                Write-Output "$(Get-TimeStamp) INFO - If .msg or .eml observed proceed " | Out-File $runLog -Append
                if ( $directoryInfo.count -gt 0 ) {
            
                    $attachments = @(@(ls $tmpFolder).Name)
                    Write-Verbose "L390 - Attachments: $attachments"

                    if ( ($attachments -like "*.msg*") )  {
                        Write-Output "$(Get-TimeStamp) INFO - Processing .msg e-mail format" | Out-File $runLog -Append
                        foreach($attachment in $attachments) {
                            Write-Output "$(Get-TimeStamp) DEBUG - Processing reported e-mail attachments: $tmpFolder$attachment" | Out-File $runLog -Append
                            Write-Output "$(Get-TimeStamp) INFO - Loading submitted .msg e-mail" | Out-File $runLog -Append
                            $msg = $outlook.Session.OpenSharedItem("$tmpFolder$attachment")
                            
                            $subject = $msg.ConversationTopic
                            Write-Output "$(Get-TimeStamp) DEBUG - Message subject: $subject" | Out-File $runLog -Append
                            $messageBody = $msg.Body
                            
                            Write-Output "$(Get-TimeStamp) DEBUG - Processing Headers" | Out-File $runLog -Append
                            $headers = $msg.PropertyAccessor.GetProperty("http://schemas.microsoft.com/mapi/proptag/0x007D001E")
                            Write-Output "$(Get-TimeStamp) DEBUG - Writing Headers: $tmpFolder\headers.txt" | Out-File $runLog -Append
                            $headers > "$tmpFolder\headers.txt"


                            Write-Output "$(Get-TimeStamp) DEBUG - Resetting $tmpFolder\links.txt" | Out-File $runLog -Append
                            #LINKS
                            #Clear links text file
                            $null > "$tmpFolder\links.txt"
						    
                            #Load links
                            #Check if HTML Body exists else populate links from Text Body
                            Write-Output "$(Get-TimeStamp) INFO - Identifying URLs" | Out-File $runLog -Append
                            if ( $($msg.HTMLBody.Length -gt 0) ) {
                                Write-Output "$(Get-TimeStamp) DEBUG - Processing URLs from message HTML body" | Out-File $runLog -Append
                                $getLinks = $URLregex.Matches($($msg.HTMLBody)).Value.Split("") | findstr http
                            } 
                            else {
                                Write-Output "$(Get-TimeStamp) DEBUG - Processing URLs from message body" | Out-File $runLog -Append
                                $info = $msg.Body
                                $getLinks = $URLregex.Matches($($info)).Value.Split("") | findstr http
                            }


                            #Identify Safelinks or No-Safelinks.  
                            [Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
                            Write-Output "$(Get-TimeStamp) INFO - Parsing links" | Out-File $runLog -Append
                            foreach ($link in $getLinks) {
                                if ($link -like "*originalsrc*" ) {
                                    Write-Output "$(Get-TimeStamp) DEBUG - Safelink Link Before: $link" | Out-File $runLog -Append
                                    Write-Verbose "Original source"
                                    Write-Verbose "Link Before: $link"
                                    $link = @(@($link.Split("`"")[1]))
                                    if ( $link -notmatch $IMGregex ) {
                                        $link >> "$tmpFolder\links.txt"
                                        Write-Output "$(Get-TimeStamp) DEBUG - Safelink Original Source Link After: $link" | Out-File $runLog -Append
                                        Write-Verbose "Link After: $link"
                                    }
                                } elseif ( $link -like "*safelinks.protection.outlook.com*" ) {
                                    Write-Verbose "Safelink source"
                                    Write-Verbose "Link Before: $link"
                                    Write-Output "$(Get-TimeStamp) DEBUG - Safelink Link Before: $link" | Out-File $runLog -Append
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
                                    if ( $link -notmatch $IMGregex ) {
                                        $link >> "$tmpFolder\links.txt"
                                        Write-Output "$(Get-TimeStamp) DEBUG - Safelink Decoded Link After: $link" | Out-File $runLog -Append
                                        Write-Verbose "Link After: $link"
                                    }
                                } else {
                                    Write-Verbose "Standard Link"
                                    $link = $URLregex.Matches($link).Value.Split("<").Split(">") | findstr http
                                    Write-Output "$(Get-TimeStamp) DEBUG - Standard Link Before: $link" | Out-File $runLog -Append
                                    if ( $link -like '*"') {
                                        $link = $link.Substring(0,$link.Length-1)
                                    }
                                    if ( $link -notmatch $IMGregex ) {
                                        $link >> "$tmpFolder\links.txt"
                                        Write-Output "$(Get-TimeStamp) DEBUG - Standard Link After: $link" | Out-File $runLog -Append
                                        Write-Verbose "Link After: $link"
                                    }
                                }
                            }
                            Write-Output "$(Get-TimeStamp) INFO - End link processing" | Out-File $runLog -Append
                        
                            #Remove empty lines
                            Write-Output "$(Get-TimeStamp) DEBUG - Removing empty lines from $tmpFolder\links.txt" | Out-File $runLog -Append
                            (Get-Content $tmpFolder\links.txt) | ? {$_.trim() -ne "" } | set-content $tmpFolder\links.txt
						
                            #Update list of unique URLs
                            Write-Output "$(Get-TimeStamp) INFO - Loading variable links from $tmpFolder\links.txt" | Out-File $runLog -Append
                            $links = type "$tmpFolder\links.txt" | Sort -Unique
                            Write-Verbose "L508 - Links:`r`n$links"

                            Write-Output "$(Get-TimeStamp) INFO - Loading variable domains from $tmpFolder\links.txt" | Out-File $runLog -Append
                            $domains = (Get-Content $tmpFolder\links.txt) | %{ ([System.Uri]$_).Host } | Select-Object -Unique

                            $countLinks = @(@(Get-Content "$tmpFolder\links.txt" | Measure-Object -Line | Select-Object Lines | Select-Object -Unique |findstr -v "Lines -") -replace "`n|`r").Trim()
                            Write-Output "$(Get-TimeStamp) INFO - Total Unique Links: $countLinks" | Out-File $runLog -Append

                            Write-Output "$(Get-TimeStamp) STATUS - Begin .msg attachment block" | Out-File $runLog -Append
                            $attachmentCount = $msg.Attachments.Count
                            Write-Output "$(Get-TimeStamp) INFO - Attachment Count: $attachmentCount" | Out-File $runLog -Append

                            if ( $attachmentCount -gt 0 ) {
                 
                                # Get the filename and location
                                $attachedFileName = @(@($msg.Attachments | Select-Object Filename | findstr -v "FileName -") -replace "`n|`r").Trim() -replace '\s',''
                                Write-Output "$(Get-TimeStamp) INFO - Attached File Name: $attachedFileName" | Out-File $runLog -Append
                                $msg.attachments|foreach {
                                    $phishingAttachment = $_.filename
                                    Write-Output "$(Get-TimeStamp) DEBUG - Attachment Name: $phishingAttachment" | Out-File $runLog -Append
                                    Write-Output "$(Get-TimeStamp) DEBUG - Checking attachment against interestingFilesRegex" | Out-File $runLog -Append
                                    If ($phishingAttachment -match $interestingFilesRegex) {
                                        Write-Output "$(Get-TimeStamp) DEBUG - Saving Attachment to destination: $tmpFolder\attachments\$attachmentName" | Out-File $runLog -Append
                                        $_.saveasfile((Join-Path $tmpFolder + "\attachments\" + $phishingAttachment))

                                        # Actions
                                
                                        # VirusTotal
                                        if ( $virusTotal -eq $true ) {
                                            Write-Output "$(Get-TimeStamp) STATUS - Plugin - Virus Total Start" | Out-File $runLog -Append
                                            $VirusTotalResults = & $pieFolder\plugins\VirusTotal-PIE.ps1 -file "$tmpFolder\attachments\$phishingAttachment" -VTApiKey "$virusTotalAPI"
                                    
                                            $VirusTotalFlagged = $VirusTotalResults | findstr flagged
                                            Write-Output "$(Get-TimeStamp) DEBUG - Virus Total Status: $VirusTotalFlagged" | Out-File $runLog -Append

                                            $VirusTotalSHA256 = $VirusTotalResults | findstr SHA256
                                            $VirusTotalSHA256 = @($VirusTotalSHA256.Split("+")[1]).Trim()

                                            $VirusTotalLink = $VirusTotalResults | findstr Link
                                            $VirusTotalLink = @($VirusTotalLink.Split("+")[1]).Trim()
                                            Write-Output "$(Get-TimeStamp) STATUS - Plugin - Virus Total End" | Out-File $runLog -Append
                                        }
                                    }
                                }
                            }

                            # Clean Up the SPAM
                            Write-Output "$(Get-TimeStamp) DEBUG - Moving e-mail message to SPAM folder" | Out-File $runLog -Append
                            $MoveTarget = $inbox.Folders.item("SPAM")
                            [void]$msg.Move($MoveTarget)
                            $spammer = $msg.SenderEmailAddress
                            Write-Output "$(Get-TimeStamp) INFO - Spammer set to: $spammer" | Out-File $runLog -Append
                            $spammerDisplayName = $msg.SenderName
                            Write-Output "$(Get-TimeStamp) INFO - Spammer Display Name set to: $spammerDisplayName" | Out-File $runLog -Append
                        }
                    } elseif ( ($attachments -like "*.eml*") )  {
                        Write-Output "$(Get-TimeStamp) INFO - Processing .eml e-mail format" | Out-File $runLog -Append
                        $emlAttachment = $attachments -like "*.eml*"
                        Write-Verbose "L604 - Attachment: $emlAttachments"
                        Write-Output "$(Get-TimeStamp) DEBUG - Processing reported e-mail attachments: $emlAttachment" | Out-File $runLog -Append
                        Write-Output "$(Get-TimeStamp) INFO - Loading submitted .eml e-mail" | Out-File $runLog -Append
                        $msg = Load-EmlFile("$tmpFolder$emlAttachment ")

                        $subject = $msg.Subject
                        Write-Output "$(Get-TimeStamp) DEBUG - Message subject: $subject" | Out-File $runLog -Append
                        Write-Verbose "L608 - Outlook Message Subject: $subject"

                        #HTML Message Body
                        #$messageBody = $msg.HTMLBody
                        #Plain text Message Body
                        $body = $msg.BodyPart.Fields | select Name, Value | Where-Object name -EQ "urn:schemas:httpmail:textdescription"
                        $messageBody = $body.Value


                        #Headers
                        Write-Output "$(Get-TimeStamp) DEBUG - Processing Headers" | Out-File $runLog -Append
                        $headers = $msg.BodyPart.Fields | select Name, Value | Where-Object name -Like "*header*"
                        Write-Output "$(Get-TimeStamp) DEBUG - Writing Headers: $tmpFolder\headers.txt" | Out-File $runLog -Append
                        echo $headers > "$tmpFolder\headers.txt"
						
					    #Clear links text file
                        Write-Output "$(Get-TimeStamp) DEBUG - Resetting $tmpFolder\links.txt" | Out-File $runLog -Append
                        $null > "$tmpFolder\links.txt"
						
                        #Load links
                        #Check if HTML Body exists else populate links from Text Body
                        Write-Output "$(Get-TimeStamp) INFO - Identifying URLs" | Out-File $runLog -Append
                        if ( $($msg.HTMLBody.Length -gt 0) ) {
                            Write-Output "$(Get-TimeStamp) DEBUG - Processing URLs from message HTML body" | Out-File $runLog -Append
                            $getLinks = $URLregex.Matches($($msg.HTMLBody)).Value.Split("") | findstr http
                        } 
                        else {
                            Write-Output "$(Get-TimeStamp) DEBUG - Processing URLs from Text body" | Out-File $runLog -Append
                            $info = $msg.TextBody
                            $getLinks = $URLregex.Matches($($info)).Value.Split("") | findstr http
                        }

                        [Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
                        Write-Output "$(Get-TimeStamp) INFO - Parsing links" | Out-File $runLog -Append
                        foreach ($link in $getLinks) {
                            Write-Output "$(Get-TimeStamp) DEBUG - Link Before: $link" | Out-File $runLog -Append
                            Write-Verbose "L636: Link Before: $link"
                            if ($link -like "*originalsrc*" ) {
                                Write-Verbose "L637: Original Source"
                                $link = @(@($link.Split("`"")[1]))
                                if ( $link -notmatch $IMGregex ) {
                                    $link >> "$tmpFolder\links.txt"
                                    Write-Output "$(Get-TimeStamp) DEBUG - Safelink Original Source Link After: $link" | Out-File $runLog -Append
                                    Write-Verbose "L642 Link After: $link"
                                }
                            } elseif ( $link -like "*safelinks.protection.outlook.com*" ) {
                                Write-Verbose "L645: Safelink source"
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
                                if ( $link -notmatch $IMGregex ) {
                                    $link >> "$tmpFolder\links.txt"
                                    Write-Output "$(Get-TimeStamp) DEBUG - Safelink Decoded Link After: $link" | Out-File $runLog -Append
                                    Write-Verbose "L659: Link After: $link"
                                }
                            } else {
                                Write-Verbose "L662: Standard Link"
                                $link = $URLregex.Matches($link).Value.Split("<").Split(">") | findstr http
                                if ( $link -like '*"') {
                                    $link = $link.Substring(0,$link.Length-1)
                                }
                                if ( $link -notmatch $IMGregex ) {
                                    $link >> "$tmpFolder\links.txt"
                                    Write-Output "$(Get-TimeStamp) DEBUG - Standard Link After: $link" | Out-File $runLog -Append
                                    Write-Verbose "L670: Link After: $link"
                                }
                            }
                        }
                        Write-Output "$(Get-TimeStamp) INFO - End link processing" | Out-File $runLog -Append
                        
                        #Remove empty lines from links.txt
                        Write-Output "$(Get-TimeStamp) DEBUG - Removing empty lines from $tmpFolder`links.txt" | Out-File $runLog -Append
                        (Get-Content $tmpFolder\links.txt) | ? {$_.trim() -ne "" } | set-content $tmpFolder\links.txt
		
	
					    #Update list of unique URLs
                        Write-Output "$(Get-TimeStamp) INFO - Loading variable links from $tmpFolder`links.txt" | Out-File $runLog -Append
                        $links = type "$tmpFolder\links.txt" | Sort -Unique
				
					    #Create list of unique FQDNs
                        Write-Output "$(Get-TimeStamp) INFO - Loading variable domains from $tmpFolder`links.txt" | Out-File $runLog -Append
                        $domains = (Get-Content $tmpFolder\links.txt) | %{ ([System.Uri]$_).Host } | Select-Object -Unique

                        $countLinks = @(@(Get-Content "$tmpFolder\links.txt" | Measure-Object -Line | Select-Object Lines | Select-Object -Unique | findstr -v "Lines -") -replace "`n|`r").Trim()
                        Write-Output "$(Get-TimeStamp) INFO - Total Unique Links: $countLinks" | Out-File $runLog -Append

                        Write-Output "$(Get-TimeStamp) STATUS - Begin .msg attachment block" | Out-File $runLog -Append
                        $attachmentCount = $msg.Attachments.Count
                        Write-Verbose "L541 - msg.AttachmentCount: $msg.Attachments.Count"
                        Write-Verbose "L541 - attachmentCount: $attachmentCount"
                        Write-Output "$(Get-TimeStamp) INFO - Attachment Count: $attachmentCount" | Out-File $runLog -Append

                        if ( $attachmentCount -gt 0 ) {                     
                            # Get the filename and location

                            $attachedFileName = @(@($msg.Attachments | Select-Object Filename | findstr -v "FileName -") -replace "`n|`r").Trim() -replace '\s',''
                            Write-Output "$(Get-TimeStamp) INFO - Attached File Name: $attachedFileName" | Out-File $runLog -Append
                            Write-Verbose "L571 - attachedFileName: $attachedFileName"
                            $msg.attachments|foreach {
                                $phishingAttachment = $_.filename
                                Write-Verbose "L574 - phishingAttachment: $phishingAttachment"
                                Write-Output "$(Get-TimeStamp) DEBUG - Attachment Name: $phishingAttachment" | Out-File $runLog -Append
                                Write-Output "$(Get-TimeStamp) DEBUG - Checking attachment against interestingFilesRegex" | Out-File $runLog -Append
                                If ($phishingAttachment -match $interestingFilesRegex) {
                                    Write-Output "$(Get-TimeStamp) DEBUG - Saving Attachment to destination: $tmpFolder\attachments\$attachmentName" | Out-File $runLog -Append
                                    Write-Host "L578 - $_.saveasfile((Join-Path $tmpFolder + `"\attachments\`" + $phishingAttachment))"
                                    Copy-Item $tmpFolder$phishingAttachment  -Destination "$tmpFolder\attachments\"
                                    #$_.saveasfile((Join-Path $tmpFolder + "\attachments\" + $phishingAttachment))

                                    # Actions
                                
                                    # VirusTotal
                                    if ( $virusTotal -eq $true ) {
                                        Write-Output "$(Get-TimeStamp) STATUS - Plugin - Virus Total Start" | Out-File $runLog -Append
                                        $VirusTotalResults = & $pieFolder\plugins\VirusTotal-PIE.ps1 -file "$tmpFolder\attachments\$phishingAttachment" -VTApiKey "$virusTotalAPI"
                                    
                                        $VirusTotalFlagged = $VirusTotalResults | findstr flagged
                                        Write-Output "$(Get-TimeStamp) DEBUG - Virus Total Status: $VirusTotalFlagged" | Out-File $runLog -Append

                                        $VirusTotalSHA256 = $VirusTotalResults | findstr SHA256
                                        $VirusTotalSHA256 = @($VirusTotalSHA256.Split("+")[1]).Trim()

                                        $VirusTotalLink = $VirusTotalResults | findstr Link
                                        $VirusTotalLink = @($VirusTotalLink.Split("+")[1]).Trim()
                                        Write-Output "$(Get-TimeStamp) STATUS - Plugin - Virus Total End" | Out-File $runLog -Append
                                    }
                                }
                            }
                        }

                    # Clean Up the SPAM
                    Write-Output "$(Get-TimeStamp) DEBUG - Moving e-mail message to SPAM folder" | Out-File $runLog -Append
                    $MoveTarget = $inbox.Folders.item("SPAM")
                    [void]$msg.Move($MoveTarget)
                    Write-Verbose "L725 Spammer Source: $($msg.From)"
                    $spammer = $msg.From.Split("<").Split(">")[1]
                    Write-Output "$(Get-TimeStamp) INFO - Spammer set to: $spammer" | Out-File $runLog -Append
                    $spammerDisplayName = $msg.From.Split("<").Split(">")[0]
                    Write-Verbose "L728 Spammer: $spammer  SpammerDisplayName: $spammerDisplayName"
                    Write-Output "$(Get-TimeStamp) INFO - Spammer Display Name set to: $spammerDisplayName" | Out-File $runLog -Append
                }
            } else {
                Write-Output "$(Get-TimeStamp) STATUS - Non .eml or .msg format" | Out-File $runLog -Append
                Write-Verbose "L 598 - Else block hit for non-msg and non-eml."
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
                #******EH Debug
                Write-Verbose "L610 - Subject info 1: $subject"
                    
                $endUserName = $reportedBy.Split("@")[0]
                
                if ($orgEmailFormat -eq 1) {
                    #E-mail format firstname.lastname@example.com
                    $endUserLastName = $endUserName.Split(".")[1]
                } elseif ($orgEmailFormat -eq 2) {
                    #Format 2 - FLastname@example.com
                    $endUserLastName = $endUserName.substring(1) -replace '[^a-zA-Z-]',''
                } elseif ($orgEmailFormat -eq 3) {
                    #Format 3 - FirstnameLastname@example.com
                    $endUserLastName = ($endUserName -creplace  '([A-Z\W_]|\d+)(?<![a-z])',' $&').trim().Split(' ')[1]
                } else {
                    Write-Host "Organization's E-mail Format must be set."
                }


                #******EH Debug
                Write-Verbose "endUserName: $endUserName endUserLastName: $endUserLastName"
                $subjectQuery = "Subject:" + "'" + $subject + "'" + " Sent:" + $day
                $subjectQuery = "'" + $subjectQuery + "'"
                #******EH Verbose
                Write-Host "Identifying variable subjectQuery: $subjectQuery"
                $searchMailboxResults = Search-Mailbox $endUserName -SearchQuery $subjectQuery -TargetMailbox "$socMailbox" -TargetFolder "PROCESSING" -LogLevel Full

                $targetFolder = $searchMailboxResults.TargetFolder
                $outlookAnalysisFolder = @(@($rootFolders.Folders | ?{$_.Name -match "PROCESSING"}).Folders).FolderPath | findstr -i $endUserLastName

                #$MoveTarget = $inbox.Folders.item("SPAM")
                #[void]$msg.Move($MoveTarget)
                #$spammer = $msg.SenderEmailAddress
                #$spammerDisplayName = $msg.SenderName
            
            
                sleep 30 
                echo $null > $analysisLog
                $companyDomain = $socMailbox.Split("@")[1]

                Get-MessageTrace -RecipientAddress $reportedBy -StartDate "$24Hours" -EndDate "$date" | Select MessageTraceID,Received,*Address,*IP,Subject,Status,Size,MessageID | Export-Csv $tmpLog -NoTypeInformation
                #$subject = $_.Split(",")[6]; $subject = $subject.Split('"')[1]
                type $tmpLog | ForEach-Object { $_ | Select-String -SimpleMatch $subject >> $analysisLog }
                (gc $analysisLog) | ? {$_.trim() -ne "" } | set-content $analysisLog
                $spammer = type $analysisLog | ForEach-Object { $_.Split(",")[2]  } | Sort | Get-Unique | findstr "@" | findstr -v "$companyDomain"
                $spammer = $spammer.Split('"')[1] | Sort | Get-Unique
            }
            # Pull more messages if the sender cannot be found (often happens when internal messages are reported)
            if (-Not $spammer.Contains("@") -eq $true) {
                Write-Verbose "L691 - Spammer not found, looking for more."
                sleep 10
                echo $null > $analysisLog
                $companyDomain = $socMailbox.Split("@")[1]

                Get-MessageTrace -RecipientAddress $reportedBy -StartDate $24Hours -EndDate $date | Select MessageTraceID,Received,*Address,*IP,Subject,Status,Size,MessageID | Export-Csv $tmpLog -NoTypeInformation
                #$subject = $_.Split(",")[6]; $subject = $subject.Split('"')[1]
                Write-Verbose "L697 - The subject var is equal to  $subject"
                type $tmpLog | ForEach-Object { $_ | Select-String -SimpleMatch $subject >> $analysisLog }
                (gc $analysisLog) | ? {$_.trim() -ne "" } | set-content $analysisLog
                       
                $spammer = "Unknown"
        }

        # Create a case folder
        Write-Output "$(Get-TimeStamp) STATUS - Creating case" | Out-File $runLog -Append
        # - Another shot
        $caseID = Get-Date -Format M-d-yyyy_h-m-s
        if ( $spammer.Contains("@") -eq $true) {
            $spammerName = $spammer.Split("@")[0]
            $spammerDomain = $spammer.Split("@")[1]
            $caseID = echo $caseID"_Sender_"$spammerName".at."$spammerDomain
        } else {
            $caseID = echo $caseID"_Sent-as-Fwd"
        }
        mkdir $caseFolder$caseID
        # Support adding Network Share Location to the Case
        $hostname = hostname
        $networkShare = "\\\\$hostname\\PIE\\cases\\$caseID\\"

        # Check for Attachments
        if ($attachmentCount -gt 0) {
            mkdir "$caseFolder$caseID\attachments\"
            $msubject = $msg.subject 
            $mBody = $msg.body 
            <# Is this needed??
            $msg.attachments|foreach { 
                $attachment = $_.filename 
                $a = $_.filename 
                If (-Not ($a -match $boringFilesRegex)) { 
                    $_.saveasfile((Join-Path $tmpFolder $a)) 
                    $fileHashes += @(Get-FileHash $tmpFolder$a -Algorithm SHA256)
                }
            }#>
            #$attachmentFull = "$caseFolder$caseID\attachments\" + $a
            
            $files = $true

            Write-Output "$(Get-TimeStamp) INFO - Moving interesting files to case folder" | Out-File $runLog -Append
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
        Write-Output "$(Get-TimeStamp) INFO - Moving attachments files into case folder" | Out-File $runLog -Append
        cp $tmpFolder$attachment $caseFolder$caseID
        Write-Output "$(Get-TimeStamp) DEBUG - SRC:$tmpFolder$attachment DST:$caseFolder$caseID" | Out-File $runLog -Append

        Write-Output "$(Get-TimeStamp) INFO - Copying links and headers" | Out-File $runLog -Append
        type "$tmpFolder\links.txt" | Sort -Unique > "$caseFolder$caseID\links.txt"
        type "$tmpFolder\headers.txt" > "$caseFolder$caseID\headers.txt"
        $msg.HTMLBody > "$caseFolder$caseID\email-source.txt"

        # Gather and count evidence
        Write-Output "$(Get-TimeStamp) STATUS - Begin gather and count evidence block" | Out-File $runLog -Append
        if ( $spammer.Contains("@") -eq $true) {
            sleep 5
            Write-Output "$(Get-TimeStamp) INFO - Collecting interesting messages" | Out-File $runLog -Append
            Get-MessageTrace -SenderAddress $spammer -StartDate $96Hours -EndDate $date | Select MessageTraceID,Received,*Address,*IP,Subject,Status,Size,MessageID | Export-Csv $analysisLog -NoTypeInformation
        }

        #Update here to remove onmicrosoft.com addresses for recipients
        Write-Output "$(Get-TimeStamp) INFO - Determine Recipients" | Out-File $runLog -Append
        $recipients = Get-Content $analysisLog | ForEach-Object { $_.split(",")[3] }
        $recipients = $recipients -replace '"', "" | Sort | Get-Unique | findstr -v "RecipientAddress"
        if ( $onMicrosoft -eq $true ) {
            Write-Output "$(Get-TimeStamp) INFO - Permitting onMicrosoft addresses" | Out-File $runLog -Append
            $messageCount = type $analysisLog | findstr -v "MessageTraceId" | Measure-Object | Select-Object Count | findstr -v "Count -"
            $deliveredMessageCount = type $analysisLog | findstr "Delivered Resolved" | Measure-Object | Select-Object Count | findstr -v "Count -"
            $failedMessageCount = type $analysisLog | findstr "Failed" | Measure-Object | Select-Object Count | findstr -v "Count -"
        } else {
            Write-Output "$(Get-TimeStamp) INFO - Filtering out onMicrosoft addresses" | Out-File $runLog -Append
            $messageCount = type $analysisLog | Where-Object {$_ -notmatch 'onmicrosoft.com'} | findstr -v "MessageTraceId" | Measure-Object | Select-Object Count | findstr -v "Count -"
            $deliveredMessageCount = type $analysisLog | Where-Object {$_ -notmatch 'onmicrosoft.com'} | findstr "Delivered Resolved" | Measure-Object | Select-Object Count | findstr -v "Count -"
            $failedMessageCount = type $analysisLog | Where-Object {$_ -notmatch 'onmicrosoft.com'} | findstr "Failed" | Measure-Object | Select-Object Count | findstr -v "Count -"
            $recipients = $recipients | Where-Object {$_ -notmatch 'onmicrosoft.com'}
        }
        $messageCount = $messageCount.Trim()
        $deliveredMessageCount = $deliveredMessageCount.Trim()
        $failedMessageCount = $failedMessageCount.Trim()
        $subjects = Get-Content $analysisLog | ForEach-Object { $_.split(",")[6] } | Sort | Get-Unique | findstr -v "Subject"
        
        # Build the Initial Summary
        Write-Output "$(Get-TimeStamp) STATUS - Begin creation of Summary" | Out-File $runLog -Append
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
#
                if ( $spammer.Contains("@") -eq $true) {
                    $caseSummary = "Phishing email from $spammer was reported on $date by $reportedBy. The subject of the email is ($subject). Initial analysis shows that $messageCount user(s) received this email in the past 96 hours."
                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -createCase "Phishing : $spammerName [at] $spammerDomain" -priority 3 -summary "$caseSummary" -token $caseAPItoken
                    sleep 5
                } else {
                    $caseSummary = "Phishing email was reported on $date by $reportedBy. The subject of the email is ($subject). Initial analysis shows that $messageCount user(s) received this email in the past 96 hours."
                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -createCase "Phishing Message Reported" -priority 3 -summary "$caseSummary" -token $caseAPItoken
                }
                $caseNumber = Get-Content "$pieFolder\plugins\case.txt"
                mv "$pieFolder\plugins\case.txt" "$caseFolder$caseID\"
                $caseURL = "https://$LogRhythmHost/cases/$caseNumber"

                Write-Output "$(Get-TimeStamp) INFO - LR API - Applying case tag" | Out-File $runLog -Append
                # Tag the case as phishing
                if ( $defaultCaseTag ) {
                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -addTag "$defaultCaseTag" -casenum $caseNumber -token $caseAPItoken
                }

                # Adding and assigning the Case Owner
                Write-Output "$(Get-TimeStamp) INFO - LR API - Assigning case owner" | Out-File $runLog -Append
                if ( $caseOwner ) {
                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -addCaseUser "$caseOwner" -casenum $caseNumber -token $caseAPItoken
                    sleep 1
                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -changeCaseOwner "$caseOwner" -casenum $caseNumber -token $caseAPItoken
                }

                # Adding and assigning other users
                Write-Output "$(Get-TimeStamp) INFO - LR API - Assigning case collaborators" | Out-File $runLog -Append
                if ( $caseCollaborators ) {
                    foreach ( $i in $caseCollaborators ) {
                        & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -addCaseUser "$i" -casenum $caseNumber -token $caseAPItoken
                        sleep 1
                    }
                }
        
                # Append Case Info to 
                Write-Output "$(Get-TimeStamp) INFO - Appending Case info to spam-report" | Out-File $runLog -Append
                echo "LogRhythm Case Information:" >> "$caseFolder$caseID\spam-report.txt"
                echo "" >> "$caseFolder$caseID\spam-report.txt"
                echo "Case #:      $caseNumber" >> "$caseFolder$caseID\spam-report.txt"
                echo "Case URL:    $caseURL" >> "$caseFolder$caseID\spam-report.txt"
                echo "" >> "$caseFolder$caseID\spam-report.txt"

                # Copy raw logs to case
                Write-Output "$(Get-TimeStamp) INFO - LR API - Copying raw logs to case" | Out-File $runLog -Append
                $caseNote = type $analysisLog
                $caseNote = $caseNote -replace '"', ""
                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Raw Phishing Logs: $caseNote" -token $caseAPItoken
                
                # Recipients
                Write-Output "$(Get-TimeStamp) INFO - LR API - Adding recipient info to case" | Out-File $runLog -Append
                $messageRecipients = (Get-Content "$caseFolder$caseID\recipients.txt") -join ", "
                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Email Recipients: $messageRecipients" -token $caseAPItoken

                # Copy E-mail Message text body to case
                Write-Output "$(Get-TimeStamp) INFO - LR API - Copying e-mail body text to case" | Out-File $runLog -Append
                if ( $messageBody ) {
                    $caseMessageBody = $($messageBody.Replace("`r`n","\r\n"))
                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Submitted Email Message Body:\r\n$caseMessageBody" -token $caseAPItoken
                }

                Write-Verbose "Number of Subjects: $($subjects.length)"
                # If multiple subjects, add subjects to case
                if ( $($subjects.Length) -gt 1 ) {
                    Write-Output "$(Get-TimeStamp) INFO - LR API - Copying summary of observed subjects to case" | Out-File $runLog -Append
                    $caseSubjects = $subjects | Out-String
                    $caseSubjects = $($caseSubjects.Replace("`r`n","\r\n"))
                    $caseSubjects = $($caseSubjects.Replace("`"",""))
                    Write-verbose "L900 - True"
                    Write-Verbose $caseSubjects
                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Subjects from sender:\r\n$caseSubjects" -token $caseAPItoken
                }

                # Observed Links
                if ( $links) {
                    Write-Output "$(Get-TimeStamp) INFO - LR API - Copying links to case" | Out-File $runLog -Append
                    $messageLinks= (Get-Content "$caseFolder$caseID\links.txt") -join "\r\n"
                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Links:\r\n$messageLinks" -token $caseAPItoken
                }

                # Remove whitelist Links from Links List
                if ($links) {
                    Write-Output "$(Get-TimeStamp) INFO - Removing whitelist links from scannable links" | Out-File $runLog -Append
                    [System.Collections.ArrayList]$scanLinks = @($links)
                    [System.Collections.ArrayList]$scanDomains = @($domains)
                    Write-Verbose "L1021 links: $links "
                    Write-Verbose "L1022 links: $scanlinks "
                    for ($i=0; $i -le $links.Count; $i++) {
                        Write-Verbose "i = $i`r`nLink = $($links[$i])"
                        foreach ($wlink in $urlWhitelist) {
                            if ($($links[$i]) -like $wlink ) {
                                Write-Output "$(Get-TimeStamp) DEBUG - Removing link: $($links[$i])" | Out-File $runLog -Append
                                Write-Verbose "L999 - Whitelisted Link, remove link from scanning for $($links[$i])."
                                $scanLinks.Remove($($links[$i])) 
                                #$i--
                            }
                        }
                    }
                    Write-Verbose "L1033 Processed Scan Links - $scanLinks"
                    # Domains
                    Write-Output "$(Get-TimeStamp) DEBUG - Removing whitelist domains from scannable domains" | Out-File $runLog -Append
                    for ($b=0; $b -le $domains.Count; $b++) {
                        Write-Verbose "b = $b`r`nLink = $($domains[$b])"
                        foreach ($wdomain in $domainWhitelist) {
                            if ($($domains[$b]) -like $wdomain ) {
                                Write-Output "$(Get-TimeStamp) DEBUG - Removing domain: $($domains[$b])" | Out-File $runLog -Append
                                Write-Verbose "L1008 - Whitelisted Domain, removed domain from scanning for $($domains[$b])."
                                $scanDomains.Remove($($domains[$b])) 
                                #$b--
                            }
                        }
                    }
                    Write-Verbose "L1044 Processed Scan Domains - $scanDomains"
                }

#>

# ================================================================================
# Third Party Integrations
# ================================================================================
#
                # WRIKE
                if ( $wrike -eq $true ) {
                    Write-Output "$(Get-TimeStamp) STATUS - Begin Wrike" | Out-File $runLog -Append
                    $secOpsSummary = "Phishing email from $spammer was reported on $date by $reportedBy. The subject of the email is ($subject). Initial analysis shows that $messageCount user(s) received this email in the past 48 hours. For more information, review the LogRhythm Case and Evidence folder."           

                    # Security Operations Contact(s)
                    & $pieFolder\plugins\wrike.ps1 -newTask "Case $caseNumber - Phishing email from $spammer" -wrikeUserName $wrikeUser -wrikeFolderName $wrikeFolder -wrikeDescription $secOpsSummary -accessToken $wrikeAPI
            
                    # Labs
                    $labsSummary = "Phishing email from $spammer was reported on $date by $reportedBy. The subject of the email is ($subject). Initial analysis shows that $messageCount user(s) received this email in the past 48 hours. For more information, review the LogRhythm Case ($LogRhythmHost/cases/$caseNumber) and Evidence folder"
                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Tasks Created in Wrike..." -token $caseAPItoken
                    Write-Output "$(Get-TimeStamp) STATUS - End Wrike" | Out-File $runLog -Append
                }

                # SCREENSHOT MACHINE
                if ( $screenshotMachine -eq $true ) {
                    if ( $scanLinks.length -gt 0 ) {
                        Write-Output "$(Get-TimeStamp) STATUS - Begin Screenshot Machine" | Out-File $runLog -Append
                        $scanLinks | ForEach-Object {
                            $splitLink = ([System.Uri]"$_").Host

                            Invoke-RestMethod "http://api.screenshotmachine.com/?key=$screenshotKey&dimension=1024x768&format=png&url=$_" -OutFile "$caseFolder$caseID\screenshot-$splitLink.png"
                    
                            $screenshotStatus = "Screenshot of hxxp://$splitLink website has been captured and saved with the case folder: screenshot-$splitLink.png"
                            & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$screenshotStatus" -token $caseAPItoken
                        }
                        Write-Output "$(Get-TimeStamp) STATUS - End Screenshot Machine" | Out-File $runLog -Append
                    }
                }

                # GET LINK INFO
                if ( $getLinkInfo -eq $true ) {
                    if ( $scanLinks.length -gt 0 ) {
                        Write-Output "$(Get-TimeStamp) STATUS - Begin LinkInfo" | Out-File $runLog -Append
                        $scanLinks | ForEach-Object { 
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
                        Write-Output "$(Get-TimeStamp) STATUS - End LinkInfo" | Out-File $runLog -Append
                    }
                }


                # PHISHTANK
                if ( $phishTank -eq $true ) {
                    if ( $scanLinks.length -gt 0 ) {
                        Write-Output "$(Get-TimeStamp) STATUS - Begin Phishtank" | Out-File $runLog -Append
                        $scanLinks | ForEach-Object { 
                        
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
                        Write-Output "$(Get-TimeStamp) STATUS - End Phishtank" | Out-File $runLog -Append
                    }
                }

                # SUCURI LINK ANALYSIS
                if ( $sucuri -eq $true ) {
                    if ( $scanDomains.length -gt 0 ) {
                        Write-Output "$(Get-TimeStamp) STATUS - Begin SUCURI" | Out-File $runLog -Append
                        $scanDomains | ForEach-Object {
                            Write-Output "$(Get-TimeStamp) INFO - Submitting domain: $_" | Out-File $runLog -Append
                            $sucuriLink = "https://sitecheck.sucuri.net/results/$_"
                            $sucuriAnalysis = iwr "https://sitecheck.sucuri.net/api/v2/?scan=$_&json"
                            $sucuriAnalysis.RawContent | Out-File $tmpFolder\sucuriAnalysis.txt

                            $skipLines = Get-Content $tmpFolder\sucuriAnalysis.txt | Measure-Object -Line
                            $sucuriResults = Get-Content $tmpFolder\sucuriAnalysis.txt | select -Skip $skipLines.Lines | ConvertFrom-Json
                            $isitblacklisted = $sucuriResults.BLACKLIST.WARN | Select-String -Pattern 'blacklist'
                            if ( !$isitblacklisted ) { 
                                $isitblacklisted = $sucuriResults.MALWARE.NOTIFICATIONS | Select-Object -Property 'Blacklist'
                            }
                            $isitcompromised = $sucuriResults.MALWARE.NOTIFICATIONS | Select-Object -Property 'Websitemalware'

                            if ( $isitblacklisted ) {
                
                                $sucuriStatus = "BLACKLISTED LINK! Sucuri has flagged this domain: $_. Full details available here: $sucuriLink."
                                $threatScore += 1

                                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$sucuriStatus" -token $caseAPItoken
                
                            } 
                
                            if ( $isitcompromised.WEBSITEMALWARE -eq $true ) {
                
                                $sucuriStatus = "MALWARE DETECTED! Sucuri has flagged this domain: $_. Full details available here: $sucuriLink."
                                $threatScore += 1
                
                                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$sucuriStatus" -token $caseAPItoken

                            }
                            if ( !$isitblacklisted -eq $true -and !$isitcompromised.WEBSITEMALWARE -eq $true ) {
                                $sucuriStatus = "Sucuri has determined $_ domain is clean.  Full details available here: $sucuriLink."

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
                        Write-Output "$(Get-TimeStamp) STATUS - End Sucuri" | Out-File $runLog -Append
                    }
                }

                # URLSCAN
                if ( $urlscan -eq $true ) {
			        if ( $scanLinks.length -gt 0 ) {
                        Write-Output "$(Get-TimeStamp) STATUS - Begin urlSCAN" | Out-File $runLog -Append
                        Write-Output "$(Get-TimeStamp) INFO - Max Links: $urlscanMax" | Out-File $runLog -Append
			
				        echo "urlscan.io" >> "$caseFolder$caseID\spam-report.txt"
				        echo "============================================================" >> "$caseFolder$caseID\spam-report.txt"

				        $scanLinks | Select-Object -First $urlscanMax | ForEach-Object {
                            Write-Output "$(Get-TimeStamp) Info - Scanning: $_" | Out-File $runLog -Append
					        & $pieFolder\plugins\URLScan.ps1 -key $urlscanAPI -link $_ -caseID $caseID -caseFolder "$caseFolder" -pieFolder "$pieFolder" -logRhythmHost $logRhythmHost -caseAPItoken $caseAPItoken -networkShare $networkShare

				        }

                        if ((Test-Path -Path "$caseFolder$caseID\urlScan\hashes.txt" -PathType Leaf)) {
                            Write-Output "$(Get-TimeStamp) Info - File Downloads Detected, info saved to: $caseFolder$caseID\urlScan\hashes.txt" | Out-File $runLog -Append
                            # Wildfire Integration: submits file hashes for URL direct download files
                            if ( $wildfire -eq $true ) {
                                Write-Output "$(Get-TimeStamp) INFO - urlScan to Wildfire submission" | Out-File $runLog -Append
                                $urlscanHashes = Get-Content "$caseFolder$caseID\urlScan\hashes.txt"
                                echo "" >> "$caseFolder$caseID\spam-report.txt"
                                if ( $urlscanHashes.Length -gt 0 ) {
                                
                                    echo "urlScan - File Hashes Observed & Palo Alto Wildfire Enabled -" >> "$caseFolder$caseID\spam-report.txt"
                                    echo "" >> "$caseFolder$caseID\spam-report.txt"

                                    $urlscanHashes | ForEach-Object {
	                                    $wfFName = $_.Split(",")[1]
                                        $wfHash = $_.Split(",")[0]
                                        Write-Output "$(Get-TimeStamp) INFO - Submitting file: $wfFname Hash: $wfHash" | Out-File $runLog -Append
	                                    echo "" >> "$caseFolder$caseID\spam-report.txt"
	                                    echo "Wildfire Analysis: File: $wfFName Hash: $wfHash" >> "$caseFolder$caseID\spam-report.txt"
	                                    & $pieFolder\plugins\Wildfire.ps1 -key $wildfireAPI -fileHash $wfHash -fileName $wfFName -caseID $caseID -caseFolder "$caseFolder" -pieFolder "$pieFolder" -logRhythmHost $logRhythmHost -caseAPItoken $caseAPItoken
	                                    echo "" >> "$caseFolder$caseID\spam-report.txt"

                                    }
                                    echo "" >> "$caseFolder$caseID\spam-report.txt"
                                    $wfFname = ""
                                    $wfHash = ""
                                }
                            }
                        }

				        echo "============================================================" >> "$caseFolder$caseID\spam-report.txt"
				        echo "" >> "$caseFolder$caseID\spam-report.txt"
                        Remove-Item -Path $tmpFolder\urlscanAnalysis.txt
                        Remove-Item -Path $tmpFolder\urlscanRequest.txt
                        Write-Output "$(Get-TimeStamp) STATUS - End urlScan" | Out-File $runLog -Append
			        }
                }

                # DOMAIN TOOLS
                if ( $domainTools -eq $true ) {
                    Write-Output "$(Get-TimeStamp) STATUS - Begin Domain Tools" | Out-File $runLog -Append

                    $domainIgnoreList = "bit.ly","ow.ly","x.co","goo.gl","logrhythm.com","google.com"
                    $threshold = (Get-Date).AddMonths(-3)
                    $threshold = $threshold.ToString("yyy-MM-dd")

                    if ( $scanLinks.length -gt 0 ) {
                        $scanLinks | ForEach-Object {
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
                    Write-Output "$(Get-TimeStamp) STATUS - End Domain Tools" | Out-File $runLog -Append
                    }
                }

                # SHODAN
                if ( $shodan -eq $true ) {
			        if ( $scanDomains.length -gt 0 ) {
                        Write-Output "$(Get-TimeStamp) STATUS - Begin Shodan" | Out-File $runLog -Append
			
				        echo "Shodan.io" >> "$caseFolder$caseID\spam-report.txt"
				        echo "============================================================" >> "$caseFolder$caseID\spam-report.txt"

				        $scanDomains | ForEach-Object {
					        echo "Shodan Analysis: $_" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "$(Get-TimeStamp) INFO - Submitting domain: $_" | Out-File $runLog -Append
					        & $pieFolder\plugins\Shodan.ps1 -key $shodanAPI -link $_ -caseID $caseID -caseFolder "$caseFolder" -pieFolder "$pieFolder" -logRhythmHost $logRhythmHost -caseAPItoken $caseAPItoken

				        }

				        echo "============================================================" >> "$caseFolder$caseID\spam-report.txt"
				        echo "" >> "$caseFolder$caseID\spam-report.txt"
                        Write-Output "$(Get-TimeStamp) STATUS - End Shodan" | Out-File $runLog -Append
			        }
                }



                # OPEN DNS
                if ( $openDNS -eq $true ) {
                    if ( $scanLinks.length -gt 0 ) {
                        Write-Output "$(Get-TimeStamp) STATUS - Start Open DNS" | Out-File $runLog -Append
                        $scanLinks | ForEach-Object {

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
                    Write-Output "$(Get-TimeStamp) STATUS - End Open DNS" | Out-File $runLog -Append
                    }
                }

                # URL VOID
                if ( $urlVoid -eq $true ) {
                    if ( $scanLinks.length -gt 0 ) {
                        Write-Output "$(Get-TimeStamp) STATUS - Begin URL Void" | Out-File $runLog -Append
                        $scanLinks | ForEach-Object {
                
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
                    Write-Output "$(Get-TimeStamp) STATUS - End URL Void" | Out-File $runLog -Append
                    }
                }

                # VIRUS TOTAL
                if ( $virusTotal -eq $true ) {
                    Write-Output "$(Get-TimeStamp) STATUS - Start Virus Total" | Out-File $runLog -Append
                    if ( $scanLinks.length -gt 0 ) {
                        if ( $virusTotalAPI ) {
                            $scanLinks | ForEach-Object {
                                $splitLink = $_.Split(":") | findstr -v http
                                Write-Output "$(Get-TimeStamp) INFO - Submitting $_" | Out-File $runLog -Append
                                $postParams = @{apikey="$virusTotalAPI";resource="$_";}
                                $VTResponse = iwr http://www.virustotal.com/vtapi/v2/url/report -Method POST -Body $postParams

                                $VTResponse = $VTResponse.Content | ConvertFrom-Json

                                $VTLink = @($VTResponse | findstr permalink).Split(":")[2]
                                $VTLink = "https:$VTLink"

                                $VTPositives = @(@($VTResponse | findstr positives).Split(":")[1]).Trim()
                                $VTPositives = [int]$VTPositives

                                if ( $VTPositives -lt 1 ) {
                                    $VTStatus = "====INFO - VIRUS TOTAL====\r\nScanned Link`: hxxp:$splitLink\r\nThe sample has been marked benign.\r\n\r\nMore information: $VTLink"
                                    Write-Output "$(Get-TimeStamp) INFO - URL Benign" | Out-File $runLog -Append
                    
                                } elseif ( $VTPositives -gt 0 ) {
                                    $VTStatus = "====WARNING - VIRUS TOTAL====\r\nMalicious Link`: hxxp:$splitLink\r\nThis sample has been flagged by $VTPositives Anti Virus engines.\r\n\r\nMore information: $VTLink"
                                    $threatScore += $VTPositives
                                    Write-Output "$(Get-TimeStamp) INFO - URL Malicious" | Out-File $runLog -Append
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
                    Write-Output "$(Get-TimeStamp) STATUS - End Virus Total" | Out-File $runLog -Append
                    }
                }

                # Wildfire
                if ( $wildfire -eq $true ) {
			        if ( $fileHashes.Length -gt 0 ) {
                        Write-Output "$(Get-TimeStamp) STATUS - Start Wildfire" | Out-File $runLog -Append
				        echo "Palo Alto Wildfire" >> "$caseFolder$caseID\spam-report.txt"
				        echo "============================================================" >> "$caseFolder$caseID\spam-report.txt"
				        echo "" >> "$caseFolder$caseID\spam-report.txt"

				        $fileHashes | ForEach-Object {
					        $wfFName = Split-Path -Path $($_.path) -Leaf
                            Write-Output "$(Get-TimeStamp) INFO - Submitting file: $wfFName Hash: $($_.hash)" | Out-File $runLog -Append
					        echo "" >> "$caseFolder$caseID\spam-report.txt"
					        echo "Wildfire Analysis: File: $caseFolder$caseID\attachments\$wfFName Hash: $($_.hash)" >> "$caseFolder$caseID\spam-report.txt"
					        & $pieFolder\plugins\Wildfire.ps1 -key $wildfireAPI -fileHash $($_.hash) -fileName $wfFName -caseID $caseID -caseFolder "$caseFolder" -pieFolder "$pieFolder" -logRhythmHost $logRhythmHost -caseAPItoken $caseAPItoken
					        echo "" >> "$caseFolder$caseID\spam-report.txt"

				        }

				        echo "" >> "$caseFolder$caseID\spam-report.txt"
				        echo "============================================================" >> "$caseFolder$caseID\spam-report.txt"
				        echo "" >> "$caseFolder$caseID\spam-report.txt"
                        Write-Output "$(Get-TimeStamp) STATUS - End Wildfire" | Out-File $runLog -Append
			        }
		        }


                # SHORT LINK ANALYSIS
                if ( $shortLink -eq $true ) {
                    if ( $scanLinks.length -gt 0 ) {
                        Write-Output "$(Get-TimeStamp) STATUS - Begin Short Link Analysis" | Out-File $runLog -Append
                        $scanLinks | ForEach-Object {

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
                    Write-Output "$(Get-TimeStamp) STATUS - End Short Link Analysis" | Out-File $runLog -Append
                    }
                }

                # Link RegEx Check
                if ( $linkRegexCheck ) {
                    if ( $scanLinks.length -gt 0 ) {
                        Write-Output "$(Get-TimeStamp) STATUS - Begin Link RegEx Check" | Out-File $runLog -Append
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
                        $scanLinks | ForEach-Object { 
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
                    Write-Output "$(Get-TimeStamp) STATUS - End Link Regex Check" | Out-File $runLog -Append
                    }
                }

                # THREAT GRID
                if ( $threatGrid -eq $true ) {
                    Write-Output "$(Get-TimeStamp) STATUS - Begin Threat Grid" | Out-File $runLog -Append
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

                        $scanLinks | ForEach-Object { 
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
                    Write-Output "$(Get-TimeStamp) STATUS - End Threat Grid" | Out-File $runLog -Append
                }

        
                # ADD SPAMMER TO LIST
                if ( $spammerList ) {
                    Write-Output "$(Get-TimeStamp) STATUS - Begin update Spammer List" | Out-File $runLog -Append
                    if ( $threatScore -gt $threatThreshold ) {
                        if ( $spammer.Contains("@") -eq $true) {
                    
                            & $pieFolder\plugins\List-API.ps1 -lrhost $LogRhythmHost -appendToList "$spammer" -listName "$spammerList" -token $caseAPItoken
                            sleep 1
                            & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Spammer ($spammer) added to Threat List ($spammerList)" -token $caseAPItoken
                
                        } else {
                
                            & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Unable to extract the spammer's email - manual analysis of the message is required" -token $caseAPItoken
                
                        }
                    }
                    Write-Output "$(Get-TimeStamp) STATUS - End update Spammer List" | Out-File $runLog -Append
                }
                #>
        
                
                # AUTO QUARANTINE ACTIONS
                if ( $autoQuarantine -eq $true ) {
                    Write-Output "$(Get-TimeStamp) STATUS - AUTO QUARANTINE Start Block" | Out-File $runLog -Append
                    if ( $threatScore -gt $threatThreshold ) {
                        Write-Output "$(Get-TimeStamp) INFO - Threat score $threatScore is greater than threshold of $threatThreshold" | Out-File $runLog -Append
                        $autoQuarantineNote = "Initiating auto-quarantine based on Threat Score of $threatScore. Copying messages to the Phishing inbox and hard-deleting from all recipient inboxes."
                        Write-Output "$(Get-TimeStamp) INFO - LR API - Case Updated" | Out-File $runLog -Append
                        & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$autoQuarantineNote" -token $caseAPItoken
                        sleep 5
                        Write-Output "$(Get-TimeStamp) INFO - Invoking 365Ninja Quarantine" | Out-File $runLog -Append
                        if ( $EncodedXMLCredentials ) {
                            & $pieFolder\plugins\O365Ninja.ps1 -scrapeMail -sender "$spammer" -nuke -caseNumber $caseNumber -encodedXMLCredentials "$EncodedXMLCredentials" -socMailbox $socMailBox -LogRhythmHost $LogRhythmHost -caseAPItoken $caseAPItoken
                        } else {
                            & $pieFolder\plugins\O365Ninja.ps1 -scrapeMail -sender "$spammer" -nuke -caseNumber $caseNumber -username $username -password $password -socMailbox $socMailBox -LogRhythmHost $LogRhythmHost -caseAPItoken $caseAPItoken
                        }
                    }

                    if ( $threatScore -lt $threatThreshold ) {
                        Write-Output "$(Get-TimeStamp) INFO - Threat score $threatScore is less than threshold of $threatThreshold" | Out-File $runLog -Append
                        $autoQuarantineNote = "Email not quarantined due to a required Threat Threshold of $threatThreshold."
                        Write-Output "$(Get-TimeStamp) INFO - LR API - Case Updated" | Out-File $runLog -Append
                        & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$autoQuarantineNote" -token $caseAPItoken
                    }

                    Write-Output "$(Get-TimeStamp) INFO - Spam-report Auto Quarantine Results Added" | Out-File $runLog -Append
                    echo "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                    echo "" >> "$caseFolder$caseID\spam-report.txt"
                    echo "Message Auto Quarantine Status:" >> "$caseFolder$caseID\spam-report.txt"
                    echo "" >> "$caseFolder$caseID\spam-report.txt"
                    echo $autoQuarantineNote >> "$caseFolder$caseID\spam-report.txt"
                    echo "" >> "$caseFolder$caseID\spam-report.txt"

                    Write-Output "$(Get-TimeStamp) STATUS - AUTO QUARANTINE End Block" | Out-File $runLog -Append
                }

                if ( $autoBan -eq $true ) {
                    Write-Output "$(Get-TimeStamp) STATUS - AUTO BAN Start Block" | Out-File $runLog -Append
                    if ( $threatScore -gt $threatThreshold ) {
                        Write-Output "$(Get-TimeStamp) INFO - Threat score $threatScore is greater than threshold of $threatThreshold" | Out-File $runLog -Append
                        $autoBanNote = "Automatically banning $spammer based on Threat Score of $threatScore."
                        Write-Output "$(Get-TimeStamp) INFO - LR API - Case Updated" | Out-File $runLog -Append
                        & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$autoBanNote" -token $caseAPItoken
                        sleep 5
                        Write-Output "$(Get-TimeStamp) INFO - Invoking 365Ninja Block Sender" | Out-File $runLog -Append
                        if ( $EncodedXMLCredentials ) {
                            & $pieFolder\plugins\O365Ninja.ps1 -blockSender -sender "$spammer" -caseNumber $caseNumber -encodedXMLCredentials "$EncodedXMLCredentials" -socMailbox $socMailBox -LogRhythmHost $LogRhythmHost -caseAPItoken $caseAPItoken
                        } else {
                            & $pieFolder\plugins\O365Ninja.ps1 -blockSender -sender "$spammer" -caseNumber $caseNumber -username $username -password $password -socMailbox $socMailBox -LogRhythmHost $LogRhythmHost -caseAPItoken $caseAPItoken
                        }
                    }

                    if ( $threatScore -lt $threatThreshold ) {
                        Write-Output "$(Get-TimeStamp) INFO - Threat score $threatScore is less than threshold of $threatThreshold" | Out-File $runLog -Append
                        $autoBanNote = "Sender ($spammer) not quarantined due to a required Threat Threshold of $threatThreshold."
                        & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$autoBanNote" -token $caseAPItoken
                    }

                    Write-Output "$(Get-TimeStamp) INFO - Spam-report Auto Ban Results Added" | Out-File $runLog -Append
                    echo "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                    echo "" >> "$caseFolder$caseID\spam-report.txt"
                    echo "Message Auto Ban Status:" >> "$caseFolder$caseID\spam-report.txt"
                    echo "" >> "$caseFolder$caseID\spam-report.txt"
                    echo $autobanNote >> "$caseFolder$caseID\spam-report.txt"
                    echo "" >> "$caseFolder$caseID\spam-report.txt"

                    Write-Output "$(Get-TimeStamp) STATUS - AUTO BAN End Block" | Out-File $runLog -Append
                }

# ================================================================================
# Case Closeout
# ================================================================================

                # Final Threat Score
                Write-Output "$(Get-TimeStamp) INFO - LR API - Threat Score" | Out-File $runLog -Append
                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Email Threat Score: $threatScore" -token $caseAPItoken

                Write-Output "$(Get-TimeStamp) INFO - Spam-report Case closeout" | Out-File $runLog -Append
                echo "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                echo "" >> "$caseFolder$caseID\spam-report.txt"
                echo "Email Threat Score: $threatScore" >> "$caseFolder$caseID\spam-report.txt"
                echo "" >> "$caseFolder$caseID\spam-report.txt"
                echo "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                echo "" >> "$caseFolder$caseID\spam-report.txt"

                Write-Output "$(Get-TimeStamp) INFO - LR API - Case closeout" | Out-File $runLog -Append
                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Case Details: $networkShare" -token $caseAPItoken
            }
            #Cleanup Variables prior to next evaluation
            Write-Output "$(Get-TimeStamp) INFO - Resetting analysis varaiables" | Out-File $runLog -Append
            $reportedBy = $null
            $reportedSubject = $null
			$endUserName = $null
			$endUserLastName = $null
			$subjectQuery = $null
			$searchMailboxResults = $null
			$targetFolder = $null
			$outlookAnalysisFolder = $null
			$companyDomain = $null
			$spammer = $null
			$spammerDisplayName = $null
			$message = $null
			$msg = $null
			$msubject = $null
			$subject = $null
			$subjects = $null
			$recipients = $null
			$messageCount = $null
			$deliveredMessageCount = $null
			$failedMessageCount = $null
			$mBody = $null
			$messageBody = $null
			$headers = $null
			$getLinks = $null
			$links = $null
			$domains = $null
			$countLinks = $null
			$attachmentCount = $null
			$attachmentFull = $null
			$attachment = $null
			$attachments = $null
			$phishingAttachment = $null
			$directoryInfo = $null
			$caseID = $null
			$summary = $null
            $scanLinks = $null
            $scanDomains = $null
        }
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

Write-Output "$(Get-TimeStamp) STATUS - Begin Reset-Log block" | Out-File $runLog -Append
$traceSize = Get-Item $traceLog
if ($traceSize.Length -gt 49MB ) {
    Start-Sleep -Seconds 30
    Reset-Log -fileName $traceLog -filesize 50mb -logcount 10
}
Reset-Log -fileName $phishLog -filesize 25mb -logcount 10
Reset-Log -fileName $runLog -filesize 50mb -logcount 10
#Reset-Log -fileName $spamTraceLog -filesize 25mb -logcount 10
Write-Output "$(Get-TimeStamp) STATUS - End Reset-Log block" | Out-File $runLog -Append
Write-Output "$(Get-TimeStamp) INFO - Close Office 365 connection" | Out-File $runLog -Append
# Kill Office365 Session and Clear Variables
Remove-PSSession $Session
Write-Output "$(Get-TimeStamp) STATUS - PIE Execution Completed" | Out-File $runLog -Append
Get-Variable -Exclude Session,banner | Remove-Variable -EA 0
