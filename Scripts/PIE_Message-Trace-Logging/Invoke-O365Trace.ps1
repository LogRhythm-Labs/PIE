
  #====================================#
  # PIE - Phishing Intelligence Engine #
  # v3.0  --  April, 2019              #
  #====================================#

# Copyright 2019 LogRhythm Inc.   
# Licensed under the MIT License. See LICENSE file in the project root for full license information.

<#

INSTALL:

    Review lines 43 through 100
        Add credentials under each specified section - Office 365 Connectivity and LogRhythm Case API Integration
        Define the folder where you will deploy the Invoke-O365MessageTrace.ps1 script from

    Review Lines 103 through 174
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
$ErrorActionPreference= 'silentlycontinue'
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
$defaultCaseTag = "PIE" # Default value - modify to match your case tagging schema. Note "PIE" tag is used with the Case Management Dashboard.
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
# Determines rate limiting for Virus Total.  Set to $false if commercial license is in use to permit more than 4 queries per minute.
$virusTotalPublic = $true


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

#Set VirusTotal runtime clock to null
$vtRunTime = $null

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

function Logger {
    Param(
        $logLevel = $tackleLevel,
        $logSev,
        $Message,
        $Verbose = $tackleVerbose
    )
    $cTime = "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
    #Create phishLog if file does not exist.
    if ( $(Test-Path $runLog -PathType Leaf) -eq $false ) {
        Set-Content $runLog -Value "PIE Powershell Runlog for $date"
        Write-Output "$cTime ALERT - No runLog detected.  Created new $runLog" | Out-File $runLog
    }
    if ($LogLevel -like "info" -Or $LogLevel -like "debug") {
        if ($logSev -like "s") {
            Write-Output "$cTime STATUS - $Message" | Out-File $runLog -Append
        } elseif ($logSev -like "a") {
            Write-Output "$cTime ALERT - $Message" | Out-File $runLog -Append
        } elseif ($logSev -like "e") {
            Write-Output "$cTime ERROR - $Message" | Out-File $runLog -Append
        }
    }
    if ($LogSev -like "i") {
        Write-Output "$cTime INFO - $Message" | Out-File $runLog -Append
    }
    if ($LogSev -like "d") {
        Write-Output "$cTime DEBUG - $Message" | Out-File $runLog -Append
    }
    Switch ($logSev) {
        e {$logSev = "ERROR"}
        s {$logSev = "STATUS"}
        a {$logSev = "ALERT"}
        i {$logSev = "INFO"}
        d {$logSev = "DEBUG"}
        default {$logSev = "LOGGER ERROR"}
    }
    if ( $Verbose -eq "True" ) {
        Write-Host "$cTime - $logSev - $Message"
    }
}

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
[regex]$URLregex = '(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?'
[regex]$IMGregex =  '(http(s?):)([/|.|\w|\s|-])*\.(?:jpg|gif|png)'


Logger -logSev "s" -Message "BEGIN NEW PIE EXECUTION"

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
        Logger -logSev "e" -Message "Could not find credentials file: $CredentialsFile"
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
    Logger -logSev "s" -Message "Established Office 365 connection"
} Catch {
    Write-Error "Access Denied..."
    Logger -logSev "e" -Message "Office 365 connection Access Denied"
    Break;
}


# ================================================================================
# MEAT OF THE PIE
# ================================================================================
Write-Output "$(Get-TimeStamp) INFO - Check for new reports " | Out-File $runLog -Append
if ( $log -eq $true) {
    if ( $autoAuditMailboxes -eq $true ) {
        Logger -logSev "i" -Message "Started Inbox Audit Update"
        # Check for mailboxes where auditing is not enabled and is limited to 1000 results
        $UnauditedMailboxes=(Get-Mailbox -Filter {AuditEnabled -eq $false}).Identity
        $UAMBCount=$UnauditedMailboxes.Count
        if ($UAMBCount -gt 0){
            Write-Host "Attempting to enable auditing on $UAMBCount mailboxes, please wait..." -ForegroundColor Cyan
            Logger -logSev "d" -Message "Attempting to enable auditing on $UAMBCount mailboxes"
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
            Logger -logSev "i" -Message "Finished attempting to enable auditing on $UAMBCount mailboxes"
            Write-Host "Finished attempting to enable auditing on $UAMBCount mailboxes." -ForegroundColor Yellow
        }
        if ($UAMBCount -eq 0){} # Do nothing, all mailboxes have auditing enabled.
        Logger -logSev "i" -Message "Completed Inbox Audit Update"
    }

    #Create phishLog if file does not exist.
    if ( $(Test-Path $phishLog -PathType Leaf) -eq $false ) {
        Set-Content $phishLog -Value "MessageTraceId,Received,SenderAddress,RecipientAddress,FromIP,ToIP,Subject,Status,Size,MessageId"
        Logger -logSev "a" -Message "No phishlog detected.  Created new $phishLog"
    }

    # scrape all mail - ongiong log generation
    # new scrape mail - by sslawter - LR Community
    Logger -logSev "s" -Message "Begin processing messageTrace"
    foreach ($page in 1..1000) {
        $messageTrace = Get-MessageTrace -StartDate $lastlogDate -EndDate $date -Page $page | Select MessageTraceID,Received,*Address,*IP,Subject,Status,Size,MessageID
        if ($messageTrace.Count -ne 0) {
            $messageTraces += $messageTrace
            Write-Verbose "Page #: $page"
            Logger -logSev "i" -Message "Processing page $page"
        }
        else {
            break
        }
    }
    $messageTracesSorted = $messageTraces | Sort-Object Received
    $messageTracesSorted | Export-Csv $traceLog -NoTypeInformation -Append
    ($messageTracesSorted | Select-Object -Last 1).Received.GetDateTimeFormats("O") | Out-File -FilePath $lastLogDateFile -Force -NoNewline
    Logger -logSev "s" -Message "Completed messageTrace"

    # Search for Reported Phishing Messages
    Logger -logSev "i" -Message "Loading previous reports to phishHistory"
    $phishHistory = Get-Content $phishLog | ConvertFrom-Csv -Header "MessageTraceID","Received","SenderAddress","RecipientAddress","FromIP","ToIP","Subject","Status","Size","MessageID"
    Logger -logSev "i" -Message "Loading current reports to phishTrace"
    $phishTrace = Get-MessageTrace -RecipientAddress $socMailbox -Status Delivered | Select MessageTraceID,Received,SenderAddress,RecipientAddress,FromIP,ToIP,Subject,Status,Size,MessageID | Sort-Object Received
    Logger -logSev "i" -Message "Writing phishTrace to $tmpLog"
    try {
        $phishTrace | Export-Csv $tmpLog -NoTypeInformation
    } Catch {
        Logger -logSev "e" -Message "Unable to export phishTrace to path $tmpLog"
    }
    
    $phishNewReports = Get-Content $tmpLog | ConvertFrom-Csv -Header "MessageTraceID","Received","SenderAddress","RecipientAddress","FromIP","ToIP","Subject","Status","Size","MessageID"
    if ((get-item $tmpLog).Length -gt 0) {
        $newReports = Compare-Object $phishHistory $phishNewReports -Property MessageTraceID -PassThru -IncludeEqual | Where-Object {$_.SideIndicator -eq '=>' } | Select-Object MessageTraceID,Received,SenderAddress,RecipientAddress,FromIP,ToIP,Subject,Status,Size,MessageID
        Logger -logSev "d" -Message "newReports Sender Address: $($newReports.SenderAddress)"
    } 
    if ($newReports -eq $null) {
        Write-Host "No phishing e-mails reported."
        Logger -logSev "i" -Message "No new reports detected"
    }
    if ($newReports -ne $null) {
        Logger -logSev "i" -Message "New reports detected reported by $($newReports.RecipientAddress)"
        Logger -logSev "i" -Message "Connecting to local inbox"
        # Connect to local inbox #and check for new mail
        $outlookInbox = 6
        $outlook = new-object -com outlook.application
        $ns = $outlook.GetNameSpace("MAPI")
        $olSaveType = "Microsoft.Office.Interop.Outlook.OlSaveAsType" -as [type]
        $rootFolders = $ns.Folders | ?{$_.Name -match $env:phishing}
        $inbox = $ns.GetDefaultFolder($outlookInbox)
        Logger -logSev "i" -Message "Connecting to local inbox complete"
        #$messages = $inbox.items
        #$phishCount = $messages.count
        
        Logger -logSev "s" -Message "Begin processing newReports"
        $newReports | ForEach-Object {
            #Add $newReport to $phishLog
            Logger -logSev "i" -Message "Adding new report to phishLog for recipient $($_.RecipientAddress)"
            echo "`"$($_.MessageTraceID)`",`"$($_.Received)`",`"$($_.SenderAddress)`",`"$($_.RecipientAddress)`",`"$($_.FromIP)`",`"$($_.ToIP)`",`"$($_.Subject)`",`"$($_.Status)`",`"$($_.Size)`",`"$($_.MessageID)`"" | Out-File $phishLog -Encoding utf8 -Append
            # Track the user who reported the message
            $reportedBy = $($_.SenderAddress)
            $reportedSubject = $($_.Subject)
            Logger -logSev "i" -Message "Sent By: $($_.SenderAddress)  reportedSubject: $reportedSubject"            
            #Access local inbox and check for new mail
            $messages = $inbox.items
            $phishCount = $messages.count

            Logger -logSev "s" -Message "Begin AutoQuarantine block"    
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
            Logger -logSev "s" -Message "End AutoQuarantine block"  

            Logger -logSev "s" -Message "Begin Phishing Analysis block"  
            # Analyze reported phishing messages, and scrape any other unreported messages    
            if ( $phishCount -gt 0 ) {
                Logger -logSev "d" -Message "phishCount > 0"
                # Set the initial Threat Score to 0 - increases as positive indicators for malware are observed during analysis
                $threatScore = 0
                # Extract reported messages
                Logger -logSev "i" -Message "Parse Outlook messages"  
                $fileHashes = $null
                foreach($message in $messages){
                    Logger -logSev "d" -Message "Outlook Message Subject: $($message.Subject)"                      
                    #Clear variable $msubject
                    $msubject = $null
                    #Match known translation issues
                    Logger -logSev "i" -Message "Filtering known bad characters in `$message.Subject: $($message.Subject)" 
                    
                    #Created regex to identify any and all odd characters in subject and replace with ?
                    $specialPattern = "[^\u0000-\u007F]"
                    if ($($message.Subject) -Match "$specialPattern") { 
                        $msubject = $message.Subject -Replace "$specialPattern","?"
                        Logger -logSev "i" -Message "Invalid characters identified, cleaning non-ASCII: $($message.Subject)" 
                        Logger -logSev "i" -Message "Post filter `$msubject: $($msubject)" 
                        $trueDat = $true 
                    } else {
                        $trueDat = $false
                        $msubject = $null
                    }
                    Logger -logSev "d" -Message "Post filter `$reportedSubject: $reportedSubject"
                    Logger -logSev "d" -Message "Post filter `$message.Subject: $($message.subject)"
                    Logger -logSev "d" -Message "Post filter `$msubject: $msubject"

                    if ($($message.Subject) -eq $reportedSubject -OR $msubject -eq $reportedSubject) {
                        Logger -logSev "i" -Message "Outlook message.subject matched reported message Subject"
                        $msubject = $message.subject
                        $mBody = $message.body
                        Logger -logSev "s" -Message "Parsing attachments"
                        $message.attachments|foreach {
                            Logger -logSev "i" -Message "File $($_.filename)"
                            $attachment = $_.filename
                            $attachmentFull = $tmpFolder+$attachment
                            $saveStatus = $null
                            If (-Not ($a -match $boringFilesRegex)) {
                                Try {
                                    $_.SaveAsFile((Join-Path $tmpFolder $attachment))
                                    $saveStatus = $true
                                } Catch {
                                    Logger -logSev "e" -Message "Unable to write $tmpFolder$($_.filename)"
                                    $saveStatus = $false
                                }
                                if ($saveStatus -eq $true) {
                                    if ($attachment -NotLike "*.msg*" -and $attachment -NotLike "*.eml*" -and $attachment -NotLike "*.jpg" -and $attachment -NotLike "*.png" -and $attachment -NotLike "*.tif") {
                                        sleep 1
                                        $fileHashes += @(Get-FileHash -Path "$attachmentFull" -Algorithm SHA256)
                                        Logger -logSev "d" -Message "Adding hash for $attachmentFull to variable fileHashes"
                                    }
                                }
                            }
                        }
                        Logger -logSev "s" -Message "End Parsing attachments"
                        Logger -logSev "i" -Message "Moving Outlook message to COMPLETED folder"
                        $MoveTarget = $inbox.Folders.item("COMPLETED")
                        [void]$message.Move($MoveTarget) 
                    }
                }
                Logger -logSev "i" -Message "Setting directoryInfo"
                $directoryInfo = Get-ChildItem $tmpFolder | findstr "\.msg \.eml" | Measure-Object
            
                Logger -logSev "i" -Message "If .msg or .eml observed proceed"
                if ( $directoryInfo.count -gt 0 ) {
                    $attachments = @(@(ls $tmpFolder).Name)

                    if ( ($attachments -like "*.msg*") )  {
                        Logger -logSev "s" -Message "Processing .msg e-mail format"
                        foreach($attachment in $attachments) {
                            Logger -logSev "d" -Message "Processing reported e-mail attachments: $tmpFolder$attachment"
                            Logger -logSev "i" -Message "Loading submitted .msg e-mail"
                            $msg = $outlook.Session.OpenSharedItem("$tmpFolder$attachment")
                            
                            $subject = $msg.ConversationTopic
                            Logger -logSev "d" -Message "Message subject: $subject"
                            $messageBody = $msg.Body
                            Logger -logSev "d" -Message "Processing Headers"
                            $headers = $msg.PropertyAccessor.GetProperty("http://schemas.microsoft.com/mapi/proptag/0x007D001E")
                            Logger -logSev "d" -Message "Writing Headers: $tmpFolder\headers.txt"
                            try {
                                $headers > "$tmpFolder\headers.txt"
                            } Catch {
                                Logger -logSev "e" -Message "Error writing to file path $tmpFolder\headers.txt"
                            }
                            
                            Logger -logSev "s" -Message "Begin Parsing URLs"
                            Logger -logSev "d" -Message "Resetting $tmpFolder\links.txt"
                            #Clear links text file
                            Try {
                                $null > "$tmpFolder\links.txt"
                            } Catch {
                                Logger -logSev "e" -Message "Error writing to file path $tmpFolder\links.txt"
                            }
						    
                            #Load links
                            #Check if HTML Body exists else populate links from Text Body
                            Logger -logSev "i" -Message "Identifying URLs"
                            if ( $($msg.HTMLBody.Length -gt 0) ) {
                                Logger -logSev "d" -Message "Processing URLs from HTML body"
                                $getLinks = $URLregex.Matches($($msg.HTMLBody)).Value.Split("") | findstr http
                            } 
                            else {
                                Logger -logSev "d" -Message "Processing URLs from Message body"
                                $info = $msg.Body
                                $getLinks = $URLregex.Matches($($info)).Value.Split("") | findstr http
                            }

                            #Identify Safelinks or No-Safelinks.  
                            [Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
                            
                            foreach ($link in $getLinks) {
                                if ($link -like "*originalsrc*" ) {
                                    Logger -logSev "d" -Message "Original Source Safelink Before: $link"
                                    $link = @(@($link.Split("`"")[1]))
                                    if ( $link -notmatch $IMGregex ) {
                                        $link >> "$tmpFolder\links.txt"
                                        Logger -logSev "d" -Message "Original Source Safelink After: $link"
                                    }
                                } elseif ( $link -like "*safelinks.protection.outlook.com*" ) {
                                    Logger -logSev "d" -Message "Encoded Safelink Before: $link"
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
                                        Logger -logSev "d" -Message "Encoded Safelink After: $link"
                                    }
                                } elseif ( $link -like "*urldefense.proofpoint.com*") {
                                    #Stage ProofPoint URLs for decode
                                    Logger -logSev "d" -Message "Proofpoint Link Before: $link"
                                    $ppEncodedLinks += $link        
                                } else {
                                    $link = $URLregex.Matches($link).Value.Split("<").Split(">") | findstr http
                                    Logger -logSev "d" -Message "Standard Link Before: $link"
                                    if ( $link -like '*"') {
                                        $link = $link.Substring(0,$link.Length-1)
                                    }
                                    if ( $link -notmatch $IMGregex ) {
                                        Try {
                                            $link >> "$tmpFolder\links.txt"
                                        } Catch {
                                            Logger -logSev -Message "Error writing to file path $tmpFolder\links.txt"
                                        }
                                        Logger -logSev "d" -Message "Standard Link After: $link"
                                    }
                                }
                            }
                            #ProofPoint URL Decode Block
                            if ( $ppEncodedLinks.Count -gt 0) {
                                $linkLen = $ppEncodedLinks.Count - 1
                                #Stage multiple URLs for decode, else stage single URL
                                if ($ppEncodedLinks.Count -gt 1) {
                                    Logger -logSev "d" -Message "Proofpoint - Building Encrypted URL Array"
                                    for ($i=0; $i -le $ppEncodedLinks.Count; $i++) {
                                        Logger -logSev "d" -Message "Proofpoint - Link $i $($ppEncodedLinks[$i])"
                                        if ($i -lt $linkLen ) {
                                            $ppEncodedLinks[$i] = $ppEncodedLinks[$i]+ "`", `""
                                        }
                                        $ppSubmitLinks += $ppEncodedLinks[$i]
                                    } 
                                } else {
                                    $ppSubmitLinks = $ppEncodedLinks
                                }
                                #Submit bulk URL decode request to Proofpoint
                                Logger -logSev "i" -Message "Proofpoint - Submitting URL list to decode API"
                                $ppDecodeRequest = Invoke-WebRequest -Method Post ` -Body "{`"urls`": [`"$ppSubmitLinks`" ]}" -Uri https://tap-api-v2.proofpoint.com/v2/url/decode ` -ContentType application/json
                                Logger -logSev "d" -Message "Proofpoint - Saving results to $tmpFolder\ppDecodeRequest.txt"
                                try {
                                    $ppDecodeRequest.RawContent | Out-File $tmpFolder\ppDecodeRequest.txt
                                } catch {
                                    Logger -logSev "e" -Message "Proofpoint - Unable to Write to File $tmpFolder\ppDecodeRequest.txt"
                                }
                                #Find WebRequest line skip and load JSON results
                                Logger -logSev "d" -Message "Proofpoint - Loading JSON results"
                                $lines = Get-Content $tmpFolder\ppDecodeRequest.txt
                                for ($i = 0; $i -le $lines.Length; $i++) {
                                    if ($lines[$i].Length -eq 0) {
                                        break
                                    }
                                }
                                $skip = $i + 1
                                $ppDecodeResults = Get-Content $tmpFolder\ppDecodeRequest.txt | Select-Object -Skip $skip | ConvertFrom-Json
                                #Write decoded URLs to links.txt
                                Logger -logSev "d" -Message "Proofpoint - Writing Decrypted Links to $tmpFolder\links.txt"
                                for ($i = 0; $i -lt $($ppDecodeResults.Length); $i++) {
                                    Logger -logSev "d" -Message "Proofpoint - Link $i $($ppDecodeResults.urls[$i].decodedUrl)"
                                    try {
                                        $ppDecodeResults.urls[$i].decodedUrl >> "$tmpFolder\links.txt"
                                    } catch {
                                        Logger -logSev "e" -Message "Proofpoint - Unable to Write to File $tmpFolder\links.txt"
                                    }
                                }
                                #Cleanup temporary files
                                try {
                                    Remove-Item -Path $tmpFolder\ppDecodeRequest.txt
                                } catch {
                                    Logger -logSev "e" -Message "Proofpoint - Unable to Delete file $tmpFolder\ppDecodeRequest.txt"
                                }
                            }
                        
                            #Remove empty lines
                            Logger -logSev "d" -Message "Removing empty lines from $tmpFolder\links.txt"
                            Try {
                                (Get-Content $tmpFolder\links.txt) | Where-Object {$_.trim() -ne "" } | Sort-Object -Unique | set-content $tmpFolder\links.txt
                            } Catch {
                                Logger -logSev "e" -Message "Unable to read/write to file $tmpFolder\links.txt"
                            }
                            #Update list of unique URLs
                            Logger -logSev "i" -Message "Loading variable links from $tmpFolder\links.txt"
                            $links = Get-Content "$tmpFolder\links.txt" | Sort-Object -Unique

                            Logger -logSev "i" -Message "Loading variable domains from $tmpFolder\links.txt"
                            $domains = (Get-Content $tmpFolder\links.txt) | %{ ([System.Uri]$_).Host } | Select-Object -Unique
                            
                            Logger -logSev "d" -Message "Writing list of unique domains to $tmpFolder\domains.txt"
                            Try {
                                $domains > "$tmpFolder\domains.txt"
                            } Catch {
                                Logger -logSev "e" -Message "Unable to write to file $tmpFolder\domains.txt"
                            }

                            Try {
                                $countLinks = @(@(Get-Content "$tmpFolder\links.txt" | Measure-Object -Line | Select-Object Lines | Select-Object -Unique |findstr -v "Lines -") -replace "`n|`r").Trim()
                                Logger -logSev "i" -Message "Total Unique Links: $countLinks"
                            } Catch {
                                Logger -logSev "e" -Message "Unable to read from file $tmpFolder\links.txt"
                            }

                            Try {
                                $countDomains = @(@(Get-Content "$tmpFolder\domains.txt" | Measure-Object -Line | Select-Object Lines | Select-Object -Unique |findstr -v "Lines -") -replace "`n|`r").Trim()
                                Logger -logSev "i" -Message "Total Unique Domains: $countDomains"
                            } Catch {
                                Logger -logSev "e" -Message "Unable to read from file $tmpFolder\domains.txt"
                            }
                            Logger -logSev "s" -Message "End Link Processing"
                            Logger -logSev "s" -Message "Begin .msg attachment block"
                            $attachmentCount = $msg.Attachments.Count
                            Logger -logSev "i" -Message "Attachment Count: $attachmentCount"
                            if ( $attachmentCount -gt 0 ) {
                                # Get the filename and location
                                $attachedFileName = @(@($msg.Attachments | Select-Object Filename | findstr -v "FileName -") -replace "`n|`r").Trim() -replace '\s',''
                                Logger -logSev "i" -Message "Attached File Name: $attachedFileName"
                                $msg.attachments|ForEach-Object {
                                    $phishingAttachment = $_.filename
                                    Logger -logSev "d" -Message "Attachment Name: $phishingAttachment"
                                    Logger -logSev "i" -Message "Checking attachment against interestingFilesRegex"
                                    If ($phishingAttachment -match $interestingFilesRegex) {
                                        Try {
                                            $_.saveasfile((Join-Path $tmpFolder + "\attachments\" + $phishingAttachment))
                                            Logger -logSev "i" -Message "Saving Attachment to destination: $tmpFolder\attachments\$attachmentName"
                                        } Catch {
                                            Logger -logSev "e" -Message "Unable to save Attachment to destination: $tmpFolder\attachments\$attachmentName"
                                        }
                                        
                                    }
                                }
                            }

                            # Clean Up the SPAM
                            Logger -logSev "d" -Message "Moving e-mail message to SPAM folder"
                            $MoveTarget = $inbox.Folders.item("SPAM")
                            [void]$msg.Move($MoveTarget)
                            $spammer = $msg.SenderEmailAddress
                            Logger -logSev "i" -Message "Spammer set to: $spammer"
                            $spammerDisplayName = $msg.SenderName
                            Logger -logSev "i" -Message "Spammer Display Name set to: $spammerDisplayName"
                        }
                    } elseif ( ($attachments -like "*.eml*") )  {
                        Logger -logSev "s" -Message "Processing .eml e-mail format"
                        $emlAttachment = $attachments -like "*.eml*"
                        Logger -logSev "d" -Message "Processing reported e-mail attachments: $emlAttachment"
                        Logger -logSev "i" -Message "Loading submitted .eml e-mail to variable msg"
                        $msg = Load-EmlFile("$tmpFolder$emlAttachment ")

                        $subject = $msg.Subject
                        Logger -logSev "d" -Message "Message subject: $subject"

                        #HTML Message Body
                        #$messageBody = $msg.HTMLBody
                        #Plain text Message Body
                        $body = $msg.BodyPart.Fields | select Name, Value | Where-Object name -EQ "urn:schemas:httpmail:textdescription"
                        $messageBody = $body.Value


                        #Headers
                        Logger -logSev "d" -Message "Processing Headers"
                        $headers = $msg.BodyPart.Fields | select Name, Value | Where-Object name -Like "*header*"
                        Logger -logSev "d" -Message "Writing Headers: $tmpFolder\headers.txt"
                        Try {
                            Write-Output $headers > "$tmpFolder\headers.txt"
                        } Catch {
                            Logger -logSev "e" -Message "Unable to write Headers to path $tmpFolder\headers.txt"
                        }
                        
                        Logger -logSev "s" -Message "Begin Parsing URLs"
                        
                        #Clear links text file
                        Logger -logSev "d" -Message "Resetting $tmpFolder\links.txt"
                        Try {
                            $null > "$tmpFolder\links.txt"
                        } Catch {
                            Logger -logSev "e" -Message "Error writing to file path $tmpFolder\links.txt"
                        }
                        
                        #Load links
                        #Check if HTML Body exists else populate links from Text Body
                        Logger -logSev "i" -Message "Identifying URLs"
                        if ( $($msg.HTMLBody.Length -gt 0) ) {
                            Logger -logSev "d" -Message "Processing URLs from message HTML body"
                            $getLinks = $URLregex.Matches($($msg.HTMLBody)).Value.Split("") | findstr http
                        } 
                        else {
                            Logger -logSev "d" -Message "Processing URLs from Text body"
                            $info = $msg.TextBody
                            $getLinks = $URLregex.Matches($($info)).Value.Split("") | findstr http
                        }

                        [Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
                        Logger -logSev "i" -Message "Parsing Links"
                        foreach ($link in $getLinks) {
                            Write-Output "$(Get-TimeStamp) DEBUG - Link Before: $link" | Out-File $runLog -Append
                            if ($link -like "*originalsrc*" ) {
                                Logger -logSev "d" -Message "Original Source Safelink Before: $link"
                                $link = @(@($link.Split("`"")[1]))
                                if ( $link -notmatch $IMGregex ) {
                                    $link >> "$tmpFolder\links.txt"
                                    Logger -logSev "d" -Message "Original Source Safelink After: $link"
                                }
                            } elseif ( $link -like "*safelinks.protection.outlook.com*" ) {
                                Logger -logSev "d" -Message "Encoded Safelink Before: $link"
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
                                    Logger -logSev "d" -Message "Encoded Safelink After: $link"
                                }
                            } elseif ( $link -like "*urldefense.proofpoint.com*") {
                                #Stage ProofPoint URLs for decode
                                Logger -logSev "d" -Message "Proofpoint Link Before: $link"
                                $ppEncodedLinks += $link 
                            } else {
                                Logger -logSev "d" -Message "Standard Link Before: $link"
                                $link = $URLregex.Matches($link).Value.Split("<").Split(">") | findstr http
                                if ( $link -like '*"') {
                                    $link = $link.Substring(0,$link.Length-1)
                                }
                                if ( $link -notmatch $IMGregex ) {
                                    $link >> "$tmpFolder\links.txt"
                                    Logger -logSev "d" -Message "Standard Link After: $link"
                                }
                            }
                        }

                        #ProofPoint URL Decode Block
                        if ( $ppEncodedLinks.Count -gt 0) {
                            $linkLen = $ppEncodedLinks.Count - 1
                            #Stage multiple URLs for decode, else stage single URL
                            if ($ppEncodedLinks.Count -gt 1) {
                                Logger -logSev "d" -Message "Proofpoint - Building Encrypted URL Array"
                                for ($i=0; $i -le $ppEncodedLinks.Count; $i++) {
                                    Logger -logSev "d" -Message "Proofpoint - Link $i $($ppEncodedLinks[$i])"
                                    if ($i -lt $linkLen ) {
                                        $ppEncodedLinks[$i] = $ppEncodedLinks[$i]+ "`", `""
                                    }
                                    $ppSubmitLinks += $ppEncodedLinks[$i]
                                } 
                            } else {
                                $ppSubmitLinks = $ppEncodedLinks
                            }
                            #Submit bulk URL decode request to Proofpoint
                            Logger -logSev "i" -Message "Proofpoint - Submitting URL list to decode API"
                            $ppDecodeRequest = Invoke-WebRequest -Method Post ` -Body "{`"urls`": [`"$ppSubmitLinks`" ]}" -Uri https://tap-api-v2.proofpoint.com/v2/url/decode ` -ContentType application/json
                            Logger -logSev "d" -Message "Proofpoint - Saving results to $tmpFolder\ppDecodeRequest.txt"
                            try {
                                $ppDecodeRequest.RawContent | Out-File $tmpFolder\ppDecodeRequest.txt
                            } catch {
                                Logger -logSev "e" -Message "Proofpoint - Unable to Write to File $tmpFolder\ppDecodeRequest.txt"
                            }
                            #Find WebRequest line skip and load JSON results
                            Logger -logSev "d" -Message "Proofpoint - Loading JSON results"
                            $lines = Get-Content $tmpFolder\ppDecodeRequest.txt
                            for ($i = 0; $i -le $lines.Length; $i++) {
                                if ($lines[$i].Length -eq 0) {
                                    break
                                }
                            }
                            $skip = $i + 1
                            $ppDecodeResults = Get-Content $tmpFolder\ppDecodeRequest.txt | Select-Object -Skip $skip | ConvertFrom-Json
                            #Write decoded URLs to links.txt
                            Logger -logSev "d" -Message "Proofpoint - Writing Decrypted Links to $tmpFolder\links.txt"
                            for ($i = 0; $i -lt $($ppDecodeResults.Length); $i++) {
                                Logger -logSev "d" -Message "Proofpoint - Link $i $($ppDecodeResults.urls[$i].decodedUrl)"
                                try {
                                    $ppDecodeResults.urls[$i].decodedUrl >> "$tmpFolder\links.txt"
                                } catch {
                                    Logger -logSev "e" -Message "Proofpoint - Unable to Write to File $tmpFolder\links.txt"
                                }
                            }
                            #Cleanup temporary files
                            try {
                                Remove-Item -Path $tmpFolder\ppDecodeRequest.txt
                            } catch {
                                Logger -logSev "e" -Message "Proofpoint - Unable to Delete file $tmpFolder\ppDecodeRequest.txt"
                            }
                        }

                        #Remove empty lines and duplicates
                        Logger -logSev "d" -Message "Removing empty lines from $tmpFolder\links.txt"
                        Try {
                            (Get-Content $tmpFolder\links.txt) | Where-Object {$_.trim() -ne "" } | Sort-Object -Unique | set-content $tmpFolder\links.txt
                        } Catch {
                            Logger -logSev "e" -Message "Unable to read/write to file $tmpFolder\links.txt"
                        }
		
                        #Update list of unique URLs
                        Logger -logSev "i" -Message "Loading variable links from $tmpFolder\links.txt"
                        $links = Get-Content "$tmpFolder\links.txt"

                        #Create list of unique Domains
                        Logger -logSev "i" -Message "Loading variable domains from $tmpFolder\links.txt"
                        $domains = (Get-Content $tmpFolder\links.txt) | %{ ([System.Uri]$_).Host } | Select-Object -Unique

                        Logger -logSev "d" -Message "Writing list of unique domains to $tmpFolder\domains.txt"
                        Try {
                            $domains > "$tmpFolder\domains.txt"
                        } Catch {
                            Logger -logSev "e" -Message "Unable to write to file $tmpFolder\domains.txt"
                        }
                        
                        Try {
                            $countLinks = @(@(Get-Content "$tmpFolder\links.txt" | Measure-Object -Line | Select-Object Lines | Select-Object -Unique |findstr -v "Lines -") -replace "`n|`r").Trim()
                            Logger -logSev "i" -Message "Total Unique Links: $countLinks"
                        } Catch {
                            Logger -logSev "e" -Message "Unable to read from file $tmpFolder\links.txt"
                        }

                        Try {
                            $countDomains = @(@(Get-Content "$tmpFolder\domains.txt" | Measure-Object -Line | Select-Object Lines | Select-Object -Unique |findstr -v "Lines -") -replace "`n|`r").Trim()
                            Logger -logSev "i" -Message "Total Unique Domains: $countDomains"
                        } Catch {
                            Logger -logSev "e" -Message "Unable to read from file $tmpFolder\domains.txt"
                        }
                        Logger -logSev "s" -Message "End Link Processing"

                        Logger -logSev "s" -Message "Begin .eml attachment block"
                        $attachmentCount = $msg.Attachments.Count
                        Logger -logSev "i" -Message "Attachment Count: $attachmentCount"

                        if ( $attachmentCount -gt 0 ) {                     
                            # Get the filename and location

                            $attachedFileName = @(@($msg.Attachments | Select-Object Filename | findstr -v "FileName -") -replace "`n|`r").Trim() -replace '\s',''
                            Logger -logSev "i" -Message "Attached File Name: $attachedFileName"
                            $msg.attachments|ForEach-Object {
                                $phishingAttachment = $_.filename
                                Logger -logSev "d" -Message "Attachment Name: $phishingAttachment"
                                Write-Output "$(Get-TimeStamp) DEBUG - Attachment Name: $phishingAttachment" | Out-File $runLog -Append
                                Logger -logSev "i" -Message "Checking attachment against interestingFilesRegex"
                                If ($phishingAttachment -match $interestingFilesRegex) {
                                    Logger -logSev "d" -Message "Saving Attachment to destination: $tmpFolder\attachments\$attachmentName"
                                    Try {
                                        Copy-Item $tmpFolder$phishingAttachment  -Destination "$tmpFolder\attachments\"
                                    } Catch {
                                        Logger -logSev "e" -Message "Unable to save Attachment to destination: $tmpFolder\attachments\$attachmentName"
                                    }
                                }
                            }
                        }

                    # Clean Up the SPAM
                    Logger -logSev "d" -Message "Moving e-mail message to SPAM folder"
                    $MoveTarget = $inbox.Folders.item("SPAM")
                    [void]$msg.Move($MoveTarget)
                    $spammer = $msg.From.Split("<").Split(">")[1]
                    Logger -logSev "i" -Message "Spammer set to: $spammer"
                    $spammerDisplayName = $msg.From.Split("<").Split(">")[0]
                    Logger -logSev "i" -Message "Spammer Display Name set to: $spammerDisplayName"
                }
            } else {
                Logger -logSev "s" -Message "Non .eml or .msg format"
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
                
                if ($orgEmailFormat -eq 1) {
                    Logger -logSev "i" -Message "E-mail format 1 - firstname.lastname@example.com"
                    #E-mail format firstname.lastname@example.com
                    $endUserLastName = $endUserName.Split(".")[1]
                } elseif ($orgEmailFormat -eq 2) {
                    Logger -logSev "i" -Message "E-mail format 2 - FLastname@example.com"
                    #Format 2 - FLastname@example.com
                    $endUserLastName = $endUserName.substring(1) -replace '[^a-zA-Z-]',''
                } elseif ($orgEmailFormat -eq 3) {
                    Logger -logSev "i" -Message "E-mail format 3 - FirstnameLastname@example.com"
                    #Format 3 - FirstnameLastname@example.com
                    $endUserLastName = ($endUserName -creplace  '([A-Z\W_]|\d+)(?<![a-z])',' $&').trim().Split(' ')[1]
                } else {
                    Logger -logSev "e" -Message "Organization's E-mail Format must be set."
                }


                Logger -logSev "d" -Message "endUserName: $endUserName endUserLastName: $endUserLastName"
                $subjectQuery = "Subject:" + "'" + $subject + "'" + " Sent:" + $day
                $subjectQuery = "'" + $subjectQuery + "'"

                $searchMailboxResults = Search-Mailbox $endUserName -SearchQuery $subjectQuery -TargetMailbox "$socMailbox" -TargetFolder "PROCESSING" -LogLevel Full

                $targetFolder = $searchMailboxResults.TargetFolder
                $outlookAnalysisFolder = @(@($rootFolders.Folders | ?{$_.Name -match "PROCESSING"}).Folders).FolderPath | findstr -i $endUserLastName       
            
                sleep 30 
                Write-Output $null > $analysisLog
                $companyDomain = $socMailbox.Split("@")[1]

                Get-MessageTrace -RecipientAddress $reportedBy -StartDate "$24Hours" -EndDate "$date" | Select MessageTraceID,Received,*Address,*IP,Subject,Status,Size,MessageID | Export-Csv $tmpLog -NoTypeInformation
                #$subject = $_.Split(",")[6]; $subject = $subject.Split('"')[1]
                Logger -logSev "d" -Message "Loading variable tmpLog"
                Try {
                    Get-Content $tmpLog | ForEach-Object { $_ | Select-String -SimpleMatch $subject >> $analysisLog }
                } Catch {
                    Logger -logSev "e" -Message "Unable to read content from variable tmpLog"
                }
                
                (gc $analysisLog) | Where-Object {$_.trim() -ne "" } | set-content $analysisLog
                $spammer = Get-Content $analysisLog | ForEach-Object { $_.Split(",")[2]  } | Sort-Object | Get-Unique | findstr "@" | findstr -v "$companyDomain"
                $spammer = $spammer.Split('"')[1] | Sort-Object | Get-Unique
            }
            # Pull more messages if the sender cannot be found (often happens when internal messages are reported)
            if (-Not $spammer.Contains("@") -eq $true) {
                Write-Verbose "L691 - Spammer not found, looking for more."
                sleep 10
                Try {
                    Write-Output $null > $analysisLog
                } Catch {
                    Logger -logSev "e" -Message "Unable to write to file $analysisLog"
                }
                
                $companyDomain = $socMailbox.Split("@")[1]

                Get-MessageTrace -RecipientAddress $reportedBy -StartDate $24Hours -EndDate $date | Select MessageTraceID,Received,*Address,*IP,Subject,Status,Size,MessageID | Export-Csv $tmpLog -NoTypeInformation
                #$subject = $_.Split(",")[6]; $subject = $subject.Split('"')[1]
                Write-Verbose "L697 - The subject var is equal to  $subject"
                Get-Content $tmpLog | ForEach-Object { $_ | Select-String -SimpleMatch $subject >> $analysisLog }
                (Get-Content $analysisLog) | Where-Object {$_.trim() -ne "" } | set-content $analysisLog
                       
                $spammer = "Unknown"
        }

        # Create a case folder
        Logger -logSev "s" -Message "Creating Case"
        # - Another shot
        $caseID = Get-Date -Format M-d-yyyy_h-m-s
        if ( $spammer.Contains("@") -eq $true) {
            $spammerName = $spammer.Split("@")[0]
            $spammerDomain = $spammer.Split("@")[1]
            Logger -logSev "d" -Message "Spammer Name: $spammerName Spammer Domain: $spammerDomain"
            $caseID = Write-Output $caseID"_Sender_"$spammerName".at."$spammerDomain
        } else {
            Logger -logSev "d" -Message "Case created as Fwd Message source"
            $caseID = Write-Output $caseID"_Sent-as-Fwd"
        }
        try {
            Logger -logSev "i" -Message "Creating Directory: $caseFolder$caseID"
            mkdir $caseFolder$caseID
        } Catch {
            Logger -logSev "e" -Message "Unable to create directory: $caseFolder$caseID"
        }
        # Support adding Network Share Location to the Case
        $hostname = hostname
        $networkShare = "\\\\$hostname\\PIE\\cases\\$caseID\\"

        # Check for Attachments
        if ($attachmentCount -gt 0) {
            Try {
                mkdir "$caseFolder$caseID\attachments\"
            } Catch {
                Logger -logSev "e" -Message "Unable to create directory: $caseFolder$caseID\attachments\"
            }
            
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

            Logger -logSev "i" -Message "Moving interesting files to case folder"
            # Make sure those files are moved
            Copy-Item "$tmpFolder\*.pdf" "$caseFolder$caseID\attachments\"
            Copy-Item "$tmpFolder\*.rar" "$caseFolder$caseID\attachments\"
            Copy-Item "$tmpFolder\*.tar" "$caseFolder$caseID\attachments\"
            Copy-Item "$tmpFolder\*.gz" "$caseFolder$caseID\attachments\"
            Copy-Item "$tmpFolder\*.xyz" "$caseFolder$caseID\attachments\"
            Copy-Item "$tmpFolder\*.zip" "$caseFolder$caseID\attachments\"
            Copy-Item "$tmpFolder\*.doc*" "$caseFolder$caseID\attachments\"
            Copy-Item "$tmpFolder\*.xls*" "$caseFolder$caseID\attachments\"
            Copy-Item "$tmpFolder\*.ppt*" "$caseFolder$caseID\attachments\"
            Copy-Item "$tmpFolder\*.dmg*" "$caseFolder$caseID\attachments\"
            Copy-Item "$tmpFolder\*.exe*" "$caseFolder$caseID\attachments\"
            Copy-Item "$tmpFolder\*.js" "$caseFolder$caseID\attachments\"
            Copy-Item "$tmpFolder\*.sha256" "$caseFolder$caseID\"
        }

        # Add evidence to the case folder
        Logger -logSev "i" -Message "Moving attachments folder into case folder"
        Try {
            Logger -logSev "d" -Message "SRC:$tmpFolder$attachment DST:$caseFolder$caseID"
            Copy-Item $tmpFolder$attachment $caseFolder$caseID
        } Catch {
            Logger -logSev "e" -Message "Error copying $tmpFolder$attachment to destination $caseFolder$caseID"
        }
        Logger -logSev "i" -Message "Copying links and headers"
        Try {
            Get-Content "$tmpFolder\links.txt" | Sort-Object -Unique > "$caseFolder$caseID\links.txt"
        } Catch {
            Logger -logSev "e" -Message "Error writing $tmpFolder\links.txt to destination $caseFolder$caseID\links.txt"
        }
        Try {
            Get-Content "$tmpFolder\domains.txt" | Sort-Object -Unique > "$caseFolder$caseID\domains.txt"
        } Catch {
            Logger -logSev "e" -Message "Error writing $tmpFolder\domains.txt to destination $caseFolder$caseID\domains.txt"
        }
        Try {
            Get-Content "$tmpFolder\headers.txt" > "$caseFolder$caseID\headers.txt"
        } Catch {
            Logger -logSev "e" -Message "$tmpFolder\headers.txt to destination $caseFolder$caseID\headers.txt"
        }
        Try {
            $reportedMsg.HTMLBody > "$caseFolder$caseID\email-source.txt"
        } Catch {
            Logger -logSev "e" -Message "Writing reportedMsg.HTMLBody to destination $caseFolder$caseID\email-source.txt"
        }


        # Gather and count evidence
        Logger -logSev "s" -Message "Begin gather and count evidence block"
        if ( $spammer.Contains("@") -eq $true) {
            sleep 5
            Logger -logSev "i" -Message "365 - Collecting interesting messages"
            Get-MessageTrace -SenderAddress $spammer -StartDate $96Hours -EndDate $date | Select MessageTraceID,Received,*Address,*IP,Subject,Status,Size,MessageID | Export-Csv $analysisLog -NoTypeInformation
        }

        #Update here to remove onmicrosoft.com addresses for recipients
        Logger -logSev "d" -Message "365 - Determining Recipients"
        $recipients = Get-Content $analysisLog | ForEach-Object { $_.split(",")[3] }
        $recipients = $recipients -replace '"', "" | Sort | Get-Unique | findstr -v "RecipientAddress"
        if ( $onMicrosoft -eq $true ) {
            Logger -logSev "d" -Message "365 - Permitting onMicrosoft addresses"
            $messageCount = Get-Content $analysisLog | findstr -v "MessageTraceId" | Measure-Object | Select-Object Count | findstr -v "Count -"
            $deliveredMessageCount = Get-Content $analysisLog | findstr "Delivered Resolved" | Measure-Object | Select-Object Count | findstr -v "Count -"
            $failedMessageCount = Get-Content $analysisLog | findstr "Failed" | Measure-Object | Select-Object Count | findstr -v "Count -"
        } else {
            Logger -logSev "d" -Message "365 - Filtering out onMicrosoft addresses onMicrosoft addresses"
            $messageCount = Get-Content $analysisLog | Where-Object {$_ -notmatch 'onmicrosoft.com'} | findstr -v "MessageTraceId" | Measure-Object | Select-Object Count | findstr -v "Count -"
            $deliveredMessageCount = Get-Content $analysisLog | Where-Object {$_ -notmatch 'onmicrosoft.com'} | findstr "Delivered Resolved" | Measure-Object | Select-Object Count | findstr -v "Count -"
            $failedMessageCount = Get-Content $analysisLog | Where-Object {$_ -notmatch 'onmicrosoft.com'} | findstr "Failed" | Measure-Object | Select-Object Count | findstr -v "Count -"
            $recipients = $recipients | Where-Object {$_ -notmatch 'onmicrosoft.com'}
        }
        $messageCount = $messageCount.Trim()
        $deliveredMessageCount = $deliveredMessageCount.Trim()
        $failedMessageCount = $failedMessageCount.Trim()
        Logger -logSev "d" -Message "365 - Message Count: $messageCount Delivered: $deliveredMessageCount Failed: $failedMessageCount"
        $subjects = Get-Content $analysisLog | ForEach-Object { $_.split(",")[6] } | Sort-Object | Get-Unique | findstr -v "Subject"
        Logger -logSev "d" -Message "365 - Subject Count: $($subjects.Count)"

        # Build the Initial Summary
        Logger -logSev "s" -Message "Creation of Summary"
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
        
                Write-Output $banner > "$caseFolder$caseID\spam-report.txt"
                Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output $summary >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "Unique Subject(s):" >> "$caseFolder$caseID\spam-report.txt"
                $subjects | ForEach-Object { Write-Output "    $_"} >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "Recipient(s): " >> "$caseFolder$caseID\spam-report.txt"
                $recipients | ForEach-Object { Write-Output "    $_"} >> "$caseFolder$caseID\spam-report.txt"
                $recipients | ForEach-Object { Write-Output "$_"} >> "$caseFolder$caseID\recipients.txt"
                Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                if ( $links ) {
                    Write-Output "Link(s):" >> "$caseFolder$caseID\spam-report.txt"
                    Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                    Get-Content "$tmpFolder\links.txt" >> "$caseFolder$caseID\spam-report.txt"
                    Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                    Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                    Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                }
                Write-Output "Message Body:" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output $messageBody >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "Message Headers:" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output $headers >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                Try {
                    Get-Content $analysisLog >> "$caseFolder$caseID\message-trace-logs.csv"
                } Catch {
                    Logger -logSev "e" -Message "Error writing analysisLog to $caseFolder$caseID\message-trace-logs.csv"
                }
                
                Try {
                    Remove-Item "$tmpFolder\*"
                } Catch {
                    Logger -logSev "e" -Message "Unable to purge contents from $tmpFolder"
                }
                
        #>
        

# ================================================================================
# LOGRHYTHM CASE MANAGEMENT AND THIRD PARTY INTEGRATIONS
# ================================================================================
#
                Logger -logSev "s" -Message "LogRhythm API - Create Case"
                if ( $spammer.Contains("@") -eq $true) {
                    Logger -logSev "d" -Message "LogRhythm API - Create Case with Sender Info"
                    $caseSummary = "Phishing email from $spammer was reported on $date by $reportedBy. The subject of the email is ($subject). Initial analysis shows that $messageCount user(s) received this email in the past 96 hours."
                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -createCase "Phishing : $spammerName [at] $spammerDomain" -priority 3 -summary "$caseSummary" -token $caseAPItoken
                    Start-Sleep 3
                } else {
                    Logger -logSev "d" -Message "LogRhythm API - Create Case without Sender Info"
                    $caseSummary = "Phishing email was reported on $date by $reportedBy. The subject of the email is ($subject). Initial analysis shows that $messageCount user(s) received this email in the past 96 hours."
                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -createCase "Phishing Message Reported" -priority 3 -summary "$caseSummary" -token $caseAPItoken
                }
                Try {
                    $caseNumber = Get-Content "$pieFolder\plugins\case.txt"
                } Catch {
                    Logger -logSev "e" -Message "Unable to read content $pieFolder\plugins\case.txt"
                }
                Try {
                    Move-Item "$pieFolder\plugins\case.txt" "$caseFolder$caseID\"
                } Catch {
                    Logger -logSev "e" -Message "Unable to move $pieFolder\plugins\case.txt to $caseFolder$caseID\"
                }
                
                $caseURL = "https://$LogRhythmHost/cases/$caseNumber"
                Logger -logSev "i" -Message "Case URL: $caseURL"

                Logger -logSev "i" -Message "LogRhythm API - Applying case tag"
                # Tag the case as phishing
                if ( $defaultCaseTag ) {
                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -addTag "$defaultCaseTag" -casenum $caseNumber -token $caseAPItoken
                }

                # Adding and assigning the Case Owner
                Logger -logSev "i" -Message "LogRhythm API - Assigning case owner"
                if ( $caseOwner ) {
                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -addCaseUser "$caseOwner" -casenum $caseNumber -token $caseAPItoken
                    sleep 1
                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -changeCaseOwner "$caseOwner" -casenum $caseNumber -token $caseAPItoken
                }

                # Adding and assigning other users
                Logger -logSev "i" -Message "LogRhythm API - Assigning case collaborators"
                if ( $caseCollaborators ) {
                    foreach ( $i in $caseCollaborators ) {
                        & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -addCaseUser "$i" -casenum $caseNumber -token $caseAPItoken
                        sleep 1
                    }
                }
        
                # Append Case Info to 
                Logger -logSev "i" -Message "LogRhythm - Adding case info to spam-report"
                Write-Output "$(Get-TimeStamp) INFO - Appending Case info to spam-report" | Out-File $runLog -Append
                Write-Output "LogRhythm Case Information:" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "Case #:      $caseNumber" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "Case URL:    $caseURL" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "" >> "$caseFolder$caseID\spam-report.txt"

                # Copy raw logs to case
                Logger -logSev "i" -Message "LogRhythm API - Copying raw logs to case"
                
                Try {
                    $caseNote = Get-Content $analysisLog
                } Catch {
                    Logger -logSev "e" -Message "Unable to read content from analysisLog"
                }
                $caseNote = $caseNote -replace '"', ""
                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Raw Phishing Logs: $caseNote" -token $caseAPItoken
                
                # Recipients
                Logger -logSev "i" -Message "LogRhythm API - Adding recipient info to case"
                Try {
                    $messageRecipients = (Get-Content "$caseFolder$caseID\recipients.txt") -join ", "
                } Catch {
                    Logger -logSev "e" -Message "Unable to read content from $caseFolder$caseID\recipients.txt"
                }
                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Email Recipients: $messageRecipients" -token $caseAPItoken

                # Copy E-mail Message text body to case
                Logger -logSev "i" -Message "LogRhythm API - Copying e-mail body text to case"
                if ( $messageBody ) {
                    $caseMessageBody = $($messageBody.Replace("`r`n","\r\n"))
                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Submitted Email Message Body:\r\n$caseMessageBody" -token $caseAPItoken
                }
				
				# Write cleaned message subject note to case notes
				if ($trueDat -eq $true) {
                    Logger -logSev "i" -Message "LogRhythm API - Copying cleaned message subject note to case"
					& $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Reported Message Subject was cleaned of special characters; see case notes folder for original.\r\n" -token $caseAPItoken
				}

                # If multiple subjects, add subjects to case
                if ( $($subjects.Length) -gt 1 ) {
                    Logger -logSev "i" -Message "LogRhythm API - Copying summary of observed subjects to case"
                    $caseSubjects = $subjects | Out-String
                    $caseSubjects = $($caseSubjects.Replace("`r`n","\r\n"))
                    $caseSubjects = $($caseSubjects.Replace("`"",""))
                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Subjects from sender:\r\n$caseSubjects" -token $caseAPItoken
                }

                # Observed Links
                if ( $links) {
                    Logger -logSev "i" -Message "LogRhythm API - Copying links to case"
                    $messageLinks= (Get-Content "$caseFolder$caseID\links.txt") -join "\r\n"
                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Links:\r\n$messageLinks" -token $caseAPItoken
                }

                # Observed Files
                if ( $fileHashes ) {
                    Logger -logSev "i" -Message "LogRhythm API - Copying file hashes to case"
                    Try {
                        $fileHashes= (Get-Content "$caseFolder$caseID\hashes.txt") -join "\r\n"
                    } Catch {
                        Logger -logSev "e" -Message "Unable to read file $caseFolder$caseID\hashes.txt"
                    }
                    
                    & $tackleFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Hashes:\r\n$fileHashes" -token $caseAPItoken
                }

                # Remove whitelist Links from Links List
                if ($links) {
                    Logger -logSev "s" -Message "Begin Whitelist Block"
                    Logger -logSev "i" -Message "Removing whitelist links from scannable links"
                    [System.Collections.ArrayList]$scanLinks = @($links)
                    [System.Collections.ArrayList]$scanDomains = @($domains)
                    Write-Verbose "L1021 links: $links "
                    Write-Verbose "L1022 links: $scanlinks "
                    for ($i=0; $i -lt $links.Count; $i++) {
                        Logger -logSev "d" -Message "Inspecting link: $($links[$i])"
                        foreach ($wlink in $urlWhitelist) {
                            if ($($links[$i]) -like $wlink ) {
                                Logger -logSev "d" -Message "Removing link: $($links[$i])"
                                $scanLinks.RemoveAt($i)
                                #$i--
                            }
                        }
                    }
                    # Domains
                    Logger -logSev "i" -Message "Removing whitelist domains from scannable domains"
                    for ($b=0; $b -lt $scanDomains.Count; $b++) {
                        Logger -logSev "d" -Message "Inspecting domain: $($scanDomains[$b])"
                        foreach ($wdomain in $domainWhitelist) {
                            if ($($scanDomains[$b]) -like $wdomain ) {
                                Logger -logSev "d" -Message "Removing domain: $($scanDomains[$b])"
                                $scanDomains.RemoveAt($b)
                            }
                        }
                    }
                    Logger -logSev "s" -Message "End Whitelist Block"
                }

#>

# ================================================================================
# Third Party Integrations
# ================================================================================
#
                Logger -logSev "s" -Message "Begin Third Party Plugins"
				# SHODAN
                if ( $shodan -eq $true ) {
			        if ( $scanDomains.length -gt 0 ) {
                        Logger -logSev "s" -Message "Begin Shodan"
			
				        Write-Output "Shodan.io" >> "$caseFolder$caseID\spam-report.txt"
				        Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"

				        $scanDomains | ForEach-Object {
                            Write-Output "Shodan Analysis: $_" >> "$caseFolder$caseID\spam-report.txt"
					        Logger -logSev "i" -Message "Submitting domain: $_"
					        & $pieFolder\plugins\Shodan.ps1 -key $shodanAPI -link $_ -caseID $caseID -caseFolder "$caseFolder" -pieFolder "$pieFolder" -logRhythmHost $logRhythmHost -caseAPItoken $caseAPItoken

				        }

				        Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
				        Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                        Logger -logSev "s" -Message "End Shodan"
			        }
                }
				
                # WRIKE
                if ( $wrike -eq $true ) {
                    Logger -logSev "s" -Message "Begin Wrike"
                    $secOpsSummary = "Phishing email from $spammer was reported on $date by $reportedBy. The subject of the email is ($subject). Initial analysis shows that $messageCount user(s) received this email in the past 48 hours. For more information, review the LogRhythm Case and Evidence folder."           

                    # Security Operations Contact(s)
                    & $pieFolder\plugins\wrike.ps1 -newTask "Case $caseNumber - Phishing email from $spammer" -wrikeUserName $wrikeUser -wrikeFolderName $wrikeFolder -wrikeDescription $secOpsSummary -accessToken $wrikeAPI
            
                    # Labs
                    $labsSummary = "Phishing email from $spammer was reported on $date by $reportedBy. The subject of the email is ($subject). Initial analysis shows that $messageCount user(s) received this email in the past 48 hours. For more information, review the LogRhythm Case ($LogRhythmHost/cases/$caseNumber) and Evidence folder"
                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Tasks Created in Wrike..." -token $caseAPItoken
                    Logger -logSev "s" -Message "End Wrike"
                }

                # SCREENSHOT MACHINE
                if ( $screenshotMachine -eq $true ) {
                    if ( $scanLinks.length -gt 0 ) {
                        Logger -logSev "s" -Message "Begin Screenshot Machine"
                        $scanLinks | ForEach-Object {
                            $splitLink = ([System.Uri]"$_").Host

                            Invoke-RestMethod "http://api.screenshotmachine.com/?key=$screenshotKey&dimension=1024x768&format=png&url=$_" -OutFile "$caseFolder$caseID\screenshot-$splitLink.png"
                    
                            $screenshotStatus = "Screenshot of hxxp://$splitLink website has been captured and saved with the case folder: screenshot-$splitLink.png"
                            & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$screenshotStatus" -token $caseAPItoken
                        }
                        Logger -logSev "s" -Message "End Screenshot Machine"
                    }
                }

                # GET LINK INFO
                if ( $getLinkInfo -eq $true ) {
                    if ( $scanLinks.length -gt 0 ) {
                        Logger -logSev "s" -Message "Begin LinkInfo"
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

                            Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "Get Link Info Status:" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output $getLinkInfoStatus >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"

                            Remove-Item -Path $tmpFolder\linkInfo.txt
                        }
                        Logger -logSev "s" -Message "End LinkInfo"
                    }
                }


                # PHISHTANK
                if ( $phishTank -eq $true ) {
                    if ( $scanLinks.length -gt 0 ) {
                        Logger -logSev "s" -Message "Begin Phishtank"
                        $scanLinks | ForEach-Object { 
                        
                            $splitLink = $_.Split(":") | findstr -v http

                            if ( $phishTankAPI ) {
                                $postParams = @{url="$_";format="xml";app_key="$phishTankAPI"}
                            } else {
                                $postParams = @{url="$_";format="xml"}
                            }
                            $phishTankResponse = Invoke-WebRequest -Uri http://checkurl.phishtank.com/checkurl/ -Method POST -Body $postParams
                            Try {
                                $phishTankResponse.Content | Out-File $tmpFolder\phishtankAnalysis.txt
                            } Catch {
                                Logger -logSev 'e' -Message "Unable to write file $tmpFolder\phishtankAnalysis.txt "
                            }
                            Try {
                                [xml]$phishTankResults = Get-Content $tmpFolder\phishtankAnalysis.txt 
                            } Catch {
                                Logger -logSev 'e' -Message "Unable to read file $tmpFolder\phishtankAnalysis.txt "
                            }
                            
                    
                            $phishTankStatus = $phishTankResults.response.results.url0.in_database
                    
                            $phishTankDetails = $phishTankResults.response.results.url0.phish_detail_page
                            $phishTankVerified = $phishTankResults.response.results.url0.verified
                            $phishTankVerifiedOn = $phishTankResults.response.results.url0.verified_at

                            if ( $phishTankStatus -eq "false" ) {
                                $phishTankStatus = "Link (hxxp:$splitLink) is not present in the PhishTank Database."
                            } elseif ( $phishTankStatus -eq "true" ) {
                                $phishTankStatus = "MALICIOUS LINK (hxxp:$splitLink) was found in the PhishTank Database! More Information: $phishTankDetails"
                                $threatScore += 1
                            }

                            & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$phishTankStatus" -token $caseAPItoken
                
                            Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "PhishTank Status:" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output $phishTankStatus >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                        
                        }
                        Try {
                            Remove-Item $tmpFolder\phishtankAnalysis.txt 
                        } Catch {
                            Logger -logSev 'e' -Message "Unable to remove file $tmpFolder\phishtankAnalysis.txt "
                        }
                        Logger -logSev "s" -Message "End PhishTank"
                    }
                }

                # SUCURI LINK ANALYSIS
                if ( $sucuri -eq $true ) {
                    if ( $scanDomains.length -gt 0 ) {
                        Logger -logSev "s" -Message "Begin Sucuri"
                        $scanDomains | ForEach-Object {
                            Logger -logSev "i" -Message "Submitting domain: $_"
							
							$sucuriLink = "https://sitecheck.sucuri.net/results/$_"
							$sucuriAnalysis = iwr "https://sitecheck.sucuri.net/api/v3/?scan=$_&json"
							$sucuriAnalysis.RawContent | Out-File $tmpFolder\sucuriAnalysis.txt
							$skipLines = Get-Content $tmpFolder\sucuriAnalysis.txt | Measure-Object -Line
							$sucuriResults = Get-Content $tmpFolder\sucuriAnalysis.txt | select -Skip $skipLines.Lines | ConvertFrom-Json
							$sucuriStatus = "==== INFO - SUCURI ====\r\nDomain scanned: $_\r\n"
							#Check for blacklisted status
							if ( $sucuriResults.blacklists -ne $null ) {
								$itBlacklisted = $true
								$blVendor = $sucuriResults.blacklists.vendor
								$blURL = $sucuriResults.blacklists.info_url
							}
							#Check for malware status
							if ( $sucuriResults.warnings.security.malware -ne $null ) {
								$itMalicious = $true
								$malwareInfo = $sucuriResults.warnings.security.malware
							}
							#Check for spammer status
							if ( $sucuriResults.warnings.security.spam -ne $null ) {
								$itSuspicious = $true
								$susInfo = $sucuriResults.warnings.security.spam
							}

							#Build report info
							if ( $itBlacklisted -eq $true ) {
								$sucuriStatus += "\r\nALERT: Blacklisted Link Reported by:\r\n"
								if ($blVendor -is [array] ) {
									for ($n=0; $n -lt $blVendor.Length; $n++) {
										$sucuriStatus += $blVendor[$n]+" - "+$blURL[$n]+"\r\n"
									}
								} else {
									$sucuriStatus += $blVendor+" - "+$blURL+"\r\n"
								}

								$sucuriStatus += "\r\n"
								$threatScore += 1
							} 
							
							if ( $itMalicious -eq $true ) {
							
								$sucuriStatus += "\r\nALERT: Malware Reported!\r\n"
								if ($malwareInfo -is [array] ) {
									for ($n=0; $n -lt $malwareInfo.Length; $n++) {
										$sucuriStatus += "Type: "+$malwareInfo[$n].type+"\r\n"+$malwareInfo[$n].msg+"\r\n\r\n"
									}
								} else {
									$sucuriStatus += "Type: "+$malwareInfo.type+"\r\n"+$malwareInfo.msg+"\r\n\r\n"
								}
								$threatScore += 1
							}

							if ( $itSuspicious -eq $true ) {
							
								$sucuriStatus += "\r\nALERT: Spammer Reported!\r\n"
								for ($n=0; $n -lt $susInfo.Length; $n++) {
									$sucuriStatus += "Type: "+$susInfo[$n].type+"\r\nDetails:"+$susInfo[$n].info_url+"\r\n\r\n"
								}
								$sucuriStatus += "\r\n"
								$threatScore += 1
							}

							if ( !$itBlacklisted -eq $true -and !$itMalware -eq $true -AND !$itSuspicious -eq $true ) {
								$sucuriStatus += "Sucuri has determined this link is clean.\r\n\r\n"
							}
							
							#Submit report info
							$sucuriStatus += "Last scanned by Sucuri on $($sucuriResults.scan.last_scan).\r\nFull details available here: $sucuriLink."
							& $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$sucuriStatus" -token $caseAPItoken
							$sucuriStatus += "\r\n**** END - SUCURI ****\r\n\r\n"
							Write-Output $sucuriStatus.Replace("\r\n","`r`n") >> "$caseFolder$caseID\spam-report.txt"
							
							#Cleanup
							Remove-Item -Path $tmpFolder\sucuriAnalysis.txt
							$itSuspicious = $false
							$itMalicious = $false
							$itBlacklisted = $false
							
                        }
                        Logger -logSev "s" -Message "End Sucuri"
                    }
                }

                # VIRUS TOTAL - Plugin Block
                if ( $virusTotal -eq $true ) {
                    if ( $virusTotalAPI ) {
	                    Logger -logSev "s" -Message "Begin VirusTotal"
	                    if ( $scanDomains.length -gt 0 ) {
	                        $scanDomains | ForEach-Object {
                                #Set VirusTotal API clock
                                if ($vtRunTime -eq $null) {
                                    Logger -logSev "d" -Message "Setting Initial VT Runtime"
                                    $vtRunTime = (Get-Date)
                                    $vtQueryCount = 0
                                } else {
                                    $vtTestTime = (Get-Date)
                                    $vtTimeDiff = New-TimeSpan -Start $vtRunTime -End $vtTestTime
                                    Write-Output "Time difference: $vtTimeDiff"
                                    #If the time differene is greater than 4, reset the API use clock to current time.
                                    if ($vtTimeDiff.Minutes -gt 0 ) {
                                        Logger -logSev "d" -Message "VT Runtime Greater than 1, resetting runtime position"
                                        $vtRunTime = (Get-Date)
                                        $vtQueryCount = 0
                                    }
                                }
		                        $vtStatus = "====INFO - Virus Total Domain====\r\n"

		                        Write-Output "$(Get-TimeStamp) INFO - Submitting Domain $_" | Out-File $runLog -Append
		                        $postParams = @{apikey="$virusTotalAPI";domain="$_";}

                                #Public API use vs Commercial logic block
                                if ( $virusTotalPublic -eq $true ) {
                                    $vtQueryCount = $vtQueryCount + 1
                                    if ($vtQueryCount -lt 5) {
                                        Logger -logSev "d" -Message "Submitting Domain#: $vtQueryCount Domain: $_"
                                        $vtResponse = iwr http://www.virustotal.com/vtapi/v2/domain/report -Method GET -Body $postParams
                                        $vtResponse = $vtResponse.Content | ConvertFrom-Json
                                        $vtResponseCode = $vtResponse.response_code
                                    } else {
                                        $vtTestTime = (Get-Date)
                                        $vtTimeDiff = New-TimeSpan -Start $vtRunTime -End $vtTestTime
                                        if ($vtTimeDiff.Minutes -gt 0 ) {
                                            #If the time difference between time values is greater than 1, new submissions can be made.  Reset the API's run clock to now.
                                            $vtRunTime = (Get-Date)
                                            $vtQueryCount = 1
                                            Logger -logSev "d" -Message "Submitting Domain#: $vtQueryCount Domain: $_"
                                            $vtResponse = iwr http://www.virustotal.com/vtapi/v2/domain/report -Method GET -Body $postParams
                                            $vtResponse = $vtResponse.Content | ConvertFrom-Json
                                            $vtResponseCode = $vtResponse.response_code
                                        } else {
                                            #Set the vtResponseCode to -1.  -1 is a self defined value for exceeding the API limit.
                                            $vtResponseCode = -1
                                        }
                                    }
                                } elseif ( $virusTotalPublic -eq $false ) {
                                    #If running under a commercial license, API call you like >:)
                                    $vtResponse = iwr http://www.virustotal.com/vtapi/v2/domain/report -Method GET -Body $postParams
                                    $vtResponse = $vtResponse.Content | ConvertFrom-Json
                                    $vtResponseCode = $vtResponse.response_code
                                }
                              

                                if ($vtResponseCode -eq 1) {
			                        Logger -logSev "i" -Message "Virus Total Response Code: 1, Results returned on domain."
                                    $vtLink = "https://www.virustotal.com/#/domain/$_"
                    
                                    [System.Collections.ArrayList]$vtDomainUrls = $vtResponse.detected_urls
                                    $vtStatus += "Scanned Domain: $_\r\n"
                                    if ($vtResponse."Alexa domain info" -ne $null) {
                                        $vtStatus += "Alexa Info: "+$vtResponse."Alexa domain info"+"\r\n"
                                    }
                                    if ($vtResponse."Webutation domain info" -ne $null) {
                                        $vtStatus += "Webutation Score: "+$vtResponse."Webutation domain info"."Safety score"+"  Verdict: "+$vtResponse."Webutation domain info".Verdict+"\r\n"
                                    }
                                    if ($vtResponse."TrendMicro category" -ne $null) {
                                        $vtStatus += "TrendMicro Category: "+$vtResponse."TrendMicro category"+"\r\n"
                                    }
                                    if ($vtResponse."Forcepoint ThreatSeeker category" -ne $null) {
                                        $vtStatus += "Forcepoint Category: "+$vtResponse."Forcepoint ThreatSeeker category"+"\r\n"
                                    }


                                    #Step through domain for URL array.
                                    for ($n=0; $n -lt $vtDomainUrls.Count; $n++) {                     
                                        for ($i=0; $i -lt $scanLinks.Count  ; $i++) {
                                            if ($($vtDomainUrls[$n].url) -eq $scanLinks[$i]) {
                                                Logger -logSev "d" -Message "Matched URL"
                                                $vtStatus += "\r\nMatched URL: "+$vtDomainUrls[$n].url+"\r\n"
                                                if ( $vtDomainUrls[$n].positives -lt 2 ) {
						        
                                                    $vtStatus += "The url has been marked benign.\r\n"
						                            Logger -logSev "i" -Message "Benign URL $($vtDomainUrls[$n].url)"
									
					                            } elseif ( $vtDomainUrls[$n].positives -gt 1 ) {
                                                    $vtStatus += "ALERT: This sample has been flagged by "+$vtDomainUrls[$n].positives+"/"+$vtDomainUrls[$n].total+" Anti Virus engines.\r\nScan Date: "+$vtDomainUrls[$n].scan_date+"\r\n"
						                            #If the url is found on the domain, and hosts malicious content increase the threatScore by the number of positives reported.
                                                    $threatScore += [int]$vtDomainUrls[$n].positives
						                            Logger -logSev "a" -Message "Malicious URL $($vtDomainUrls[$n].url)"
					                            }
                                                $vtDomainUrls.RemoveAt($n)
                                            }                 
                                        }
                                        if ( $vtDomainUrls[$n].positives -gt 2 ) {
                                            $tempThreat = [int]$vtDomainUrls[$n].positives
                                            $vtStatus += "\r\nALERT: A domain sample has been flagged by "+$vtDomainUrls[$n].positives+"/"+$vtDomainUrls[$n].total+" Anti Virus engines.\r\nURL: "+$vtDomainUrls[$n].url+"\r\nScan Date: "+$vtDomainUrls[$n].scan_date+"\r\n\r\n"
                                            Logger -logSev "a" -Message "Malicious URL hosted by Domain: $($vtDomainUrls[$n].url)"
				                        }

                                    }
                                    if ( $tempThreat -gt 0 ) {
                                        #If the domain hosts malicious content at other URLs outside of the specific URLs contained within the e-mail, increase threat by 1
                                        $threatScore += 1
                                    } elseif ($vtDomainUrls.Count -gt 0) {
                                        $vtStatus += "\r\nDomain URL Summary: Virus Total holds "+$vtDomainUrls.Count+" entries each with benign sample results."+"\r\n"
                                    }

                                    $vtStatus += "\r\nVirusTotal report: $vtLink"
		                        } elseif ($vtResponseCode -eq 0) {
			                        Logger -logSev "i" -Message "Response Code: 0, Domain not found in VT Database"
			                        $vtStatus += "\r\nDomain`: $_ not found in VirusTotal database.\r\n"
		                        } elseif ($vtResponseCode -eq -1) {
                                    Logger -logSev "i" -Message "Response Code: -1, Rate limit exceeded for public API use."
			                        $vtStatus += "\r\nDomain`: $_ not submitted.  Rate limit exceeded for public API use.\r\n"
                                } else {
			                        Logger -logSev "e" -Message "Response Code: -1, VirusTotal File Plugin Error."
			                        $vtStatus += "\r\nA PIE Plugin error has occured for this plugin.  Please contact your administrator.\r\n"
		                        }
                                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$vtStatus" -token $caseAPItoken
                                $vtStatus += "\r\n====END - VirusTotal Domain====\r\n"
                                Write-Output $vtStatus.Replace("\r\n","`r`n") >> "$caseFolder$caseID\spam-report.txt"
                                                              
                                #cleanup vars
                                $vtResponseCode = ""
                                $vtStatus = ""
                                $vtPositives = ""
                                $vtResponse = ""
                                $vtFName = ""
                                $vtHash = ""
                                $tempThreat = ""
	                        }
	                        Logger -logSev "s" -Message "End Virus Total Domain Plugin"
                        } 
	                    if ( $fileHashes.Length -gt 0 ) {
		                    $fileHashes | ForEach-Object {
                                #Set VirusTotal API clock
                                if ($vtRunTime -eq $null) {
                                    Logger -logSev "d" -Message "Setting Initial VT Runtime"
                                    $vtRunTime = (Get-Date)
                                    $vtQueryCount = 0
                                } else {
                                    $vtTestTime = (Get-Date)
                                    $vtTimeDiff = New-TimeSpan -Start $vtRunTime -End $vtTestTime
                                    #If the time differene is greater than 4, reset the API use clock to current time.
                                    if ($vtTimeDiff.Minutes -gt 0 ) {
                                        Logger -logSev "d" -Message "VT Runtime Greater than 1, resetting runtime position"
                                        $vtRunTime = (Get-Date)
                                        $vtQueryCount = 0
                                    }
                                }
			                    $vtFName = Split-Path -Path $($_.path) -Leaf
			                    $vtHash = [string]$($_.hash)

			                    Logger -logSev "i" -Message "Submitting file: $vtFName Hash: $vtHash"
			                    $postParams = @{apikey="$virusTotalAPI";resource="$vtHash";}
                                
                                #Public API use vs Commercial logic block
                                if ( $virusTotalPublic -eq $true ) {
                                    $vtQueryCount = $vtQueryCount + 1
                                    if ($vtQueryCount -lt 5) {
                                        $vtResponse = iwr http://www.virustotal.com/vtapi/v2/file/report -Method POST -Body $postParams
                                    } else {
                                        $vtTestTime = (Get-Date)
                                        $vtTimeDiff = New-TimeSpan -Start $vtRunTime -End $vtTestTime
                                        if ($vtTimeDiff.Minutes -gt 0 ) {
                                            #If the time difference between time values is greater than 4, new submissions can be made.  Reset the API's run clock to now.
                                            $vtRunTime = (Get-Date)
                                            $vtResponse = iwr http://www.virustotal.com/vtapi/v2/file/report -Method POST -Body $postParams
                                        } else {
                                            #Set the vtResponseCode to -1.  -1 is a self defined value for exceeding the API limit.
                                            $vtResponseCode = -1
                                        }
                                    }
                                } elseif ( $virusTotalPublic -eq $false ) {
                                    #If running under a commercial license, API call you like >:)
                                    $vtResponse = iwr http://www.virustotal.com/vtapi/v2/file/report -Method POST -Body $postParams
                                } 

			                    $vtStatus = "====INFO - Virus Total File====\r\n"

			                    $vtResponse = $vtResponse.Content | ConvertFrom-Json
			                    $vtResponseCode = $vtResponse.response_code
			                    if ($vtResponseCode -eq 1) {
				                    $vtLink = $vtResponse.permalink

				                    $vtPositives = [int]$vtResponse.positives
				                    $VTTotal = $vtResponse.total
				                    $VTScanDate = $vtResponse.scan_date

				                    if ( $vtPositives -lt 1 ) {
					                    $vtStatus += "Status: Benign\r\nFile`: $vtFName\r\nSHA256: $vtHash\r\n\r\nThe sample has been marked benign by $VTTotal Anti Virus engines."
					                    Logger -logSev "i" -Message "File Benign"
									
				                    } elseif ( $vtPositives -gt 0 ) {
					                    $vtStatus += "Status: Malicious\r\nFile`: $vtFName\r\nSHA256: $vtHash\r\n\r\nALERT: This sample has been flagged by $vtPositives/$VTTotal Anti Virus engines."
					                    $threatScore += $vtPositives
					                    Logger -logSev "a" -Message "File Malicious"
				                    }

				                    $vtStatus += "\r\n\r\nLast scanned by Virus Total on $VTScanDate.\r\nFull details available here: $vtLink."
				                    Write-Host "Entry found in VT database"
			                    } elseif ($vtResponseCode -eq 0) {
				                    Logger -logSev "i" -Message "File not found in VT Database"
				                    $vtStatus += "\r\nFile`: $vtFName not found in VirusTotal database.\r\n"
			                    } else {
				                    Logger -logSev "e" -Message "VirusTotal File Plugin Error"
				                    $vtStatus += "\r\nA PIE Plugin error has occured for this plugin.  Please contact your administrator.\r\n"
			                    }
								
			                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$vtStatus" -token $caseAPItoken
                                $vtStatus += "\r\n====END - VirusTotal FILE====\r\n"
			                    Write-Output $vtStatus.Replace("\r\n","`r`n") >> "$caseFolder$caseID\spam-report.txt"
                                #cleanup vars
                                $vtStatus = ""
                                $vtPositives = ""
                                $vtResponse = ""
                                $vtFName = ""
                                $vtHash = ""
		                    }
                            Logger -logSev "s" -Message "End VirusTotal File Plugin"
	                    }
                    } else {
	                    Logger -logSev "e" -Message "VirusTotal Plugin Enabled but no API key provided"
	                    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "VirusTotal API key required to check / submit samples." -token $caseAPItoken
                    }
                    Logger -logSev "s" -Message "End VirusTotal Plugin"
                }

                # URLSCAN
                if ( $urlscan -eq $true ) {
			        if ( $scanLinks.length -gt 0 ) {
                        Logger -logSev "s" -Message "Begin urlScan"
                        Logger -logSev "i" -Message "Max Links: $urlscanMax"
			
				        Write-Output "urlscan.io" >> "$caseFolder$caseID\spam-report.txt"
				        Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"

				        $scanLinks | Select-Object -First $urlscanMax | ForEach-Object {
                            Logger -logSev "i" -Message "Scanning: $_"
					        & $pieFolder\plugins\URLScan.ps1 -key $urlscanAPI -link $_ -caseID $caseID -caseFolder "$caseFolder" -pieFolder "$pieFolder" -logRhythmHost $logRhythmHost -caseAPItoken $caseAPItoken -networkShare $networkShare

				        }

                        if ((Test-Path -Path "$caseFolder$caseID\urlScan\hashes.txt" -PathType Leaf)) {
                            Logger -logSev "i" -Message "urlScan to Wildfire file hash submission"
                            # Wildfire Integration: submits file hashes for URL direct download files
                            if ( $wildfire -eq $true ) {
                                Write-Output "$(Get-TimeStamp) INFO - urlScan to Wildfire file submission" | Out-File $runLog -Append
                                $urlscanHashes = Get-Content "$caseFolder$caseID\urlScan\hashes.txt"
                                Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                                if ( $urlscanHashes.Length -gt 0 ) {
                                
                                    Write-Output "urlScan - File Hashes Observed & Palo Alto Wildfire Enabled -" >> "$caseFolder$caseID\spam-report.txt"
                                    Write-Output "" >> "$caseFolder$caseID\spam-report.txt"

                                    $urlscanHashes | ForEach-Object {
	                                    $wfFName = $_.Split(",")[1]
                                        $wfHash = $_.Split(",")[0]
                                        Logger -logSev "i" -Message "Submitting file: $wfFname Hash: $wfHash"
	                                    Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
	                                    Write-Output "Wildfire Analysis: File: $wfFName Hash: $wfHash" >> "$caseFolder$caseID\spam-report.txt"
	                                    & $pieFolder\plugins\Wildfire.ps1 -key $wildfireAPI -fileHash $wfHash -fileName $wfFName -caseID $caseID -caseFolder "$caseFolder" -pieFolder "$pieFolder" -logRhythmHost $logRhythmHost -caseAPItoken $caseAPItoken
	                                    Write-Output "" >> "$caseFolder$caseID\spam-report.txt"

                                    }
                                    Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                                    $wfFname = ""
                                    $wfHash = ""
                                }
                            }
                            if ( $virusTotal -eq $true ) {
                                Logger -logSev "i" -Message "urlScan to VirusTotal file submission"
                                $urlscanHashes = Get-Content "$caseFolder$caseID\urlScan\hashes.txt"
                                Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                                if ( $urlscanHashes.Length -gt 0 ) {
                                    #Set VirusTotal API clock
                                    if ($vtRunTime -eq $null) {
                                        Logger -logSev "d" -Message "Setting Initial VT Runtime"
                                        $vtRunTime = (Get-Date)
                                        $vtQueryCount = 0
                                    } else {
                                        $vtTestTime = (Get-Date)
                                        $vtTimeDiff = New-TimeSpan -Start $vtRunTime -End $vtTestTime
                                        #If the time differene is greater than 1, reset the API use clock to current time.
                                        if ($vtTimeDiff.Minutes -gt 0 ) {
                                            Logger -logSev "d" -Message "VT Runtime Greater than 1, resetting runtime position"
                                            $vtRunTime = (Get-Date)
                                            $vtQueryCount = 0
                                        }
                                    }
                                    Write-Output "urlScan - File Hashes Observed & Virus Total Enabled -" >> "$caseFolder$caseID\spam-report.txt"
                                    Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                                    $urlscanHashes | ForEach-Object {
                                        $vtFName = $_.Split(",")[1]
								        $vtHash = $_.Split(",")[0]

								        Logger -logSev "i" -Message "Submitting file: $vtFName Hash: $vtHash"
								        $postParams = @{apikey="$virusTotalAPI";resource="$vtHash";}
                                        if ( $virusTotalPublic -eq $true ) {
                                            $vtQueryCount = $vtQueryCount + 1
                                            if ($vtQueryCount -lt 5) {
                                                $vtResponse = iwr http://www.virustotal.com/vtapi/v2/file/report -Method POST -Body $postParams
                                            } else {
                                                $vtTestTime = (Get-Date)
                                                $vtTimeDiff = New-TimeSpan -Start $vtRunTime -End $vtTestTime
                                                if ($vtTimeDiff.Minutes -gt 0 ) {
                                                    #If the time difference between time values is greater than 4, new submissions can be made.  Reset the API's run clock to now.
                                                    $vtRunTime = (Get-Date)
                                                    $vtResponse = iwr http://www.virustotal.com/vtapi/v2/file/report -Method POST -Body $postParams
                                                } else {
                                                    #Set the vtResponseCode to -1.  -1 is a self defined value for exceeding the API limit.
                                                    $vtResponseCode = -1
                                                }
                                            }
                                        } elseif ( $virusTotalPublic -eq $false ) {
                                            #If running under a commercial license, API call you like >:)
                                            $vtResponse = iwr http://www.virustotal.com/vtapi/v2/file/report -Method POST -Body $postParams
                                        } 
								        $vtStatus = "====INFO - urlScan to Virus Total File====\r\nurlScan observed file download link.  File hash for downloadable file submitted to Virus Total.\r\n"

								        $vtResponse = $vtResponse.Content | ConvertFrom-Json
								        $vtResponseCode = $vtResponse.response_code
								        if ($vtResponseCode -eq 1) {
									        $vtLink = $vtResponse.permalink

									        $vtPositives = [int]$vtResponse.positives
									        $VTTotal = $vtResponse.total
									        $VTScanDate = $vtResponse.scan_date

									        if ( $vtPositives -lt 1 ) {
										        $vtStatus += "Status: Benign\r\nFile`: $vtFName\r\nSHA256: $vtHash\r\n\r\nThe sample has been marked benign by $VTTotal Anti Virus engines."
										        Logger -logSev "i" -Message "File Benign"
									
									        } elseif ( $vtPositives -gt 0 ) {
										        $vtStatus += "Status: Malicious\r\nFile`: $vtFName\r\nSHA256: $vtHash\r\n\r\nALERT: This sample has been flagged by $vtPositives/$VTTotal Anti Virus engines."
										        $threatScore += $vtPositives
										        Logger -logSev "a" -Message "File Malicious"
									        }

									        $vtStatus += "\r\n\r\nLast scanned by Virus Total on $VTScanDate.\r\nFull details available here: $vtLink."
									        Write-Host "Entry found in VT database"
								        } elseif ($vtResponseCode -eq 0) {
									        Logger -logSev "i" -Message "File not found in VT Database"
									        $vtStatus += "\r\nFile`: $vtFName not found in VirusTotal database.\r\n"
								        } elseif ($vtResponseCode -eq -1) {
                                            Logger -logSev "i" -Message "File not submitted to Virus Total.\r\nRate limit exceeded for public API use."
									        $vtStatus += "\r\nFile`: $vtFName not submitted.  Rate limit exceeded for public API use.\r\n"
                                        } else {
									        Logger -logSev "e" -Message "VirusTotal File Plugin Error"
									        $vtStatus += "\r\nA PIE Plugin error has occured for this plugin.  Please contact your administrator.\r\n"
								        }
								
								        & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$vtStatus" -token $caseAPItoken
                                        $vtStatus += "\r\n====END - VirusTotal File====\r\n"
								        Write-Output $vtStatus.Replace("\r\n","`r`n") >> "$caseFolder$caseID\spam-report.txt"
                                        #cleanup vars
                                        $vtStatus = ""
                                        $vtPositives = ""
                                        $vtResponse = ""
                                        $vtFName = ""
                                        $vtHash = ""
                                    }

                                }
                            }
                        }

				        Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                        Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                        Try {
                            Remove-Item -Path $tmpFolder\urlscanAnalysis.txt
                        } Catch {
                            Logger -logSev "e" -Message "Unable to remove file $tmpFolder\urlscanAnalysis.txt"
                        }
                        Try {
                            Remove-Item -Path $tmpFolder\urlscanRequest.txt
                        } Catch {
                            Logger -logSev "e" -Message "Unable to remove file $tmpFolder\urlscanRequest.txt"
                        }
                        Logger -logSev "s" -Message "End urlScan"
			        }
                }

                # DOMAIN TOOLS
                if ( $domainTools -eq $true ) {
                    Logger -logSev "s" -Message "Begin Domain Tools"

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

                            Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "Domain Tools Status:" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output $domainToolsUpdate >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                        }
                        Logger -logSev "s" -Message "End Domain Tools"
                    }
                }

                # OPEN DNS
                if ( $openDNS -eq $true ) {
                    if ( $scanLinks.length -gt 0 ) {
                        Logger -logSev "s" -Message "Start OpenDNS"
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

                            Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "OpenDNS Status:" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output $OpenDNSStatus >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                        }
                        Logger -logSev "s" -Message "End Domain Tools"
                    }
                }

                # URL VOID
                if ( $urlVoid -eq $true ) {
                    if ( $scanLinks.length -gt 0 ) {
                        Logger -logSev "s" -Message "Begin URLVoid"
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

                            Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "URL Void Domain Information (hxxp://$splitLink):" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output $urlVoidIPdetails >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                        }
                        Logger -logSev "s" -Message "End URLVoid"
                    }
                }


                # Wildfire
                if ( $wildfire -eq $true ) {
			        if ( $fileHashes.Length -gt 0 ) {
                        Logger -logSev "s" -Message "Begin WIldfire"
				        Write-Output "Palo Alto Wildfire" >> "$caseFolder$caseID\spam-report.txt"
				        Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
				        Write-Output "" >> "$caseFolder$caseID\spam-report.txt"

				        $fileHashes | ForEach-Object {
					        $wfFName = Split-Path -Path $($_.path) -Leaf
                            Write-Output "$(Get-TimeStamp) INFO - Submitting file: $wfFName Hash: $($_.hash)" | Out-File $runLog -Append
					        Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
					        Write-Output "Wildfire Analysis: File: $caseFolder$caseID\attachments\$wfFName Hash: $($_.hash)" >> "$caseFolder$caseID\spam-report.txt"
					        & $pieFolder\plugins\Wildfire.ps1 -key $wildfireAPI -fileHash $($_.hash) -fileName $wfFName -caseID $caseID -caseFolder "$caseFolder" -pieFolder "$pieFolder" -logRhythmHost $logRhythmHost -caseAPItoken $caseAPItoken
					        Write-Output "" >> "$caseFolder$caseID\spam-report.txt"

				        }

				        Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
				        Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                        Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                        Logger -logSev "s" -Message "End Wildfire"
			        }
		        }


                # SHORT LINK ANALYSIS
                if ( $shortLink -eq $true ) {
                    if ( $scanLinks.length -gt 0 ) {
                        Logger -logSev "s" -Message "Begin ShortLink Analysis"
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
                        Logger -logSev "s" -Message "End ShortLink Analysis"
                    }
                }

                # Link RegEx Check
                if ( $linkRegexCheck ) {
                    if ( $scanLinks.length -gt 0 ) {
                        Logger -logSev "s" -Message "Begin link RegEx Check"
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

                            Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "RegEx Check Status:" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output $regExCheckStatus >> "$caseFolder$caseID\spam-report.txt"
                            Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                        }
                        Logger -logSev "s" -Message "End Link Regex Check"
                    }
                }

                # THREAT GRID
                if ( $threatGrid -eq $true ) {
                    Logger -logSev "s" -Message "Begin ThreatGrid"
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
                    Logger -logSev "s" -Message "End ThreatGrid"
                }

        
                # ADD SPAMMER TO LIST
                if ($spamTracker -eq $true) {
                    if ( $spammerList ) {
                        Logger -logSev "s" -Message "Begin update Spammer List"
                        if ( $threatScore -gt 1 ) {
                            if ( $spammer.Contains("@") -eq $true) {
                    
                                & $pieFolder\plugins\List-API.ps1 -lrhost $LogRhythmHost -appendToList "$spammer" -listName "$spammerList" -token $caseAPItoken
                                sleep 1
                                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Spammer ($spammer) added to Threat List ($spammerList)" -token $caseAPItoken
                
                            } else {
                                $spammerStatus = "====PIE - Add Spammer to List====\r\nUnable to extract the spammer's e-mail. \r\nManual analysis of message is required."
                                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase $spammerStatus -token $caseAPItoken
                
                            }
                        }
                        Logger -logSev "s" -Message "End update Spammer List"
                    }
                }
                #>
        
                
                # AUTO QUARANTINE ACTIONS
                if ( $autoQuarantine -eq $true ) {
                    Logger -logSev "s" -Message "Begin AUTO QUARANTINE Block"
                    if ( $threatScore -gt $threatThreshold ) {
                        Logger -logSev "i" -Message "Threat score $threatScore is greater than threshold of $threatThreshold"
                        $autoQuarantineNote = "Initiating auto-quarantine based on Threat Score of $threatScore. Copying messages to the Phishing inbox and hard-deleting from all recipient inboxes."
                        Logger -logSev "i" -Message "LogRhythm API - Case Updated"
                        & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$autoQuarantineNote" -token $caseAPItoken
                        sleep 5
                        Logger -logSev "i" -Message "Invoking 365Ninja Quarantine"
                        if ( $EncodedXMLCredentials ) {
                            & $pieFolder\plugins\O365Ninja.ps1 -scrapeMail -sender "$spammer" -nuke -caseNumber $caseNumber -encodedXMLCredentials "$EncodedXMLCredentials" -socMailbox $socMailBox -LogRhythmHost $LogRhythmHost -caseAPItoken $caseAPItoken
                        } else {
                            & $pieFolder\plugins\O365Ninja.ps1 -scrapeMail -sender "$spammer" -nuke -caseNumber $caseNumber -username $username -password $password -socMailbox $socMailBox -LogRhythmHost $LogRhythmHost -caseAPItoken $caseAPItoken
                        }
                    }

                    if ( $threatScore -lt $threatThreshold ) {
                        Logger -logSev "i" -Message "Threat score $threatScore is less than threshold of $threatThreshold"
                        $autoQuarantineNote = "Email not quarantined due to a required Threat Threshold of $threatThreshold."
                        Logger -logSev "i" -Message "LogRhythm API - Case Updated"
                        & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$autoQuarantineNote" -token $caseAPItoken
                    }
                    Logger -logSev "i" -Message "Spam-report Auto Quarantine Results Added"
                    Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                    Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                    Write-Output "Message Auto Quarantine Status:" >> "$caseFolder$caseID\spam-report.txt"
                    Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                    Write-Output $autoQuarantineNote >> "$caseFolder$caseID\spam-report.txt"
                    Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                    Logger -logSev "s" -Message "End AUTO QUARANTINE Block"
                }

                if ( $autoBan -eq $true ) {
                    Logger -logSev "s" -Message "Begin AUTO BAN Block"
                    if ( $threatScore -gt $threatThreshold ) {
                        Logger -logSev "i" -Message "Threat score $threatScore is greater than threshold of $threatThreshold"
                        Logger -logSev "i" -Message "Automatically banning $spammer based on Threat Score of $threatScore."
                        Logger -logSev "i" -Message "LogRhythm API - Case Updated"
                        & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$autoBanNote" -token $caseAPItoken
                        sleep 5
                        Logger -logSev "i" -Message "Invoking 365Ninja Block Sender"
                        if ( $EncodedXMLCredentials ) {
                            & $pieFolder\plugins\O365Ninja.ps1 -blockSender -sender "$spammer" -caseNumber $caseNumber -encodedXMLCredentials "$EncodedXMLCredentials" -socMailbox $socMailBox -LogRhythmHost $LogRhythmHost -caseAPItoken $caseAPItoken
                        } else {
                            & $pieFolder\plugins\O365Ninja.ps1 -blockSender -sender "$spammer" -caseNumber $caseNumber -username $username -password $password -socMailbox $socMailBox -LogRhythmHost $LogRhythmHost -caseAPItoken $caseAPItoken
                        }
                    }

                    if ( $threatScore -lt $threatThreshold ) {
                        Logger -logSev "i" -Message "Threat score $threatScore is less than threshold of $threatThreshold"
                        $autoBanNote = "Sender ($spammer) not quarantined due to a required Threat Threshold of $threatThreshold."
                        Logger -logSev "i" -Message "LogRhythm API - Case Updated"
                        & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$autoBanNote" -token $caseAPItoken
                    }

                    Logger -logSev "i" -Message "Spam-report Auto Ban Results Added"
                    Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                    Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                    Write-Output "Message Auto Ban Status:" >> "$caseFolder$caseID\spam-report.txt"
                    Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                    Write-Output $autobanNote >> "$caseFolder$caseID\spam-report.txt"
                    Write-Output "" >> "$caseFolder$caseID\spam-report.txt"

                    Logger -logSev "s" -Message "End AUTO BAN Block"
                }

# ================================================================================
# Case Closeout
# ================================================================================

                # Final Threat Score
                Logger -logSev "i" -Message "LogRhythm API - Add Threat Score"
                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Email Threat Score: $threatScore" -token $caseAPItoken

                Logger -logSev "i" -Message "Spam-report Case closeout"
                Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "Email Threat Score: $threatScore" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "============================================================" >> "$caseFolder$caseID\spam-report.txt"
                Write-Output "" >> "$caseFolder$caseID\spam-report.txt"

                Logger -logSev "i" -Message "LogRhythm API - Add network share details"
                & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "Case Details: $networkShare" -token $caseAPItoken
            }
            #Cleanup Variables prior to next evaluation
            Logger -logSev "s" -Message "Resetting analysis varaiables"
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
            $trueDat = $null
            $fileHashes = $null
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

Logger -logSev "s" -Message "Begin Reset-Log block"
$traceSize = Get-Item $traceLog
if ($traceSize.Length -gt 49MB ) {
    Start-Sleep -Seconds 30
    Reset-Log -fileName $traceLog -filesize 50mb -logcount 10
}
Reset-Log -fileName $phishLog -filesize 25mb -logcount 10
Reset-Log -fileName $runLog -filesize 50mb -logcount 10
#Reset-Log -fileName $spamTraceLog -filesize 25mb -logcount 10
Logger -logSev "s" -Message "End Reset-Log block"
Logger -logSev "i" -Message "Close Office 365 connection"
# Kill Office365 Session and Clear Variables
Remove-PSSession $Session
Logger -logSev "s" -Message "PIE Execution Completed"
Get-Variable -Exclude Session,banner | Remove-Variable -EA 0
