
  #====================================#
  # PIE - Phishing Intelligence Engine #
  # LogRhythm Security Operations      #
  # greg . foss @ logrhythm . com      #
  # v1.0  --  November, 2017           #
  #====================================#

# Copyright 2017 LogRhythm Inc.   
# Licensed under the MIT License. See LICENSE file in the project root for full license information.

<#

INSTALL:

    Review lines 40 through 72
        Add credentials under each specified section - Office 365 Connectivity and LogRhythm Case API Integration
        Define the folder where you will deploy the Invoke-O365MessageTrace.ps1 script from

USAGE:

    Configure as a scheduled task to run every 5-minutes:
        powershell.exe Invoke-O365Trace.ps1

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
$PlainText = $false

# XML Configuration - store credentials in an encoded XML (best option)
if ( $EncodedXMLCredentials ) {
    #
    # To generate the XML:
    #      PS C:\> Get-Credential | Export-Clixml Service-Account_cred.xml
    #
    $CredentialsFile = "C:\Path-To-Credentials-File.xml"
}

# Plain Text Credentials (not recommended)
if ( $PlainText ) {
    $username = "SERVICE ACCOUNT USERNAME"
    $password = "SERVICE ACCOUNT PASSWORD"
}

# Case Folders and Logging
$logFolder = "C:\PIE-INSTALL-DIRECTORY"

# ================================================================================
# END GLOBAL PARAMETERS
# ************************* DO NOT EDIT BELOW THIS LINE *************************
# ================================================================================


# ================================================================================
# DATE, FILE, AND GLOBAL EMAIL PARSING
# ================================================================================

# Folder Structure
$traceLog = "$logFolder\logs\ongoing-trace-log.csv"
$lastLogDateFile = "$logFolder\logs\last-log-date.txt"
$log = $true

# Date Variables
$date = Get-Date
$oldAF = (Get-Date).AddDays(-10)
$48Hours = (Get-Date).AddHours(-48)
$24Hours = (Get-Date).AddHours(-24)
$inceptionDate = (Get-Date).AddMinutes(-6)
$phishDate = (Get-Date).AddMinutes(-7)
$day = Get-Date -Format MM-dd-yyyy

#Enables picking up e-mail message trace where last left off - by sslawter - LR Community
try {
    $lastLogDate = [DateTime]::SpecifyKind((Get-Content -Path $lastLogDateFile),'Utc')
}
catch {
    $lastLogDate = $inceptionDate
}



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
    Write-Host "Access Denied..."
}


# ================================================================================
# Office 365 Message Trace Logging
# ================================================================================

if ( $log -eq $true) {

    # scrape all mail - ongiong log generation - Updated by sslawter - LR Community
    foreach ($page in 1..1000) {
        $messageTrace = Get-MessageTrace -StartDate $lastlogDate -EndDate $date -Page $page | Select MessageTraceID,Received,*Address,*IP,Subject,Status,Size,MessageID
        if ($messageTrace.Count -ne 0) {
            $messageTraces += $messageTrace
            Write-Verbose "Page #: $page"
        }
        else {
            break
        }
    }
    $messageTracesSorted = $messageTraces | Sort-Object Received
    $messageTracesSorted | Export-Csv $traceLog -NoTypeInformation -Append
    ($messageTracesSorted | Select-Object -Last 1).Received.GetDateTimeFormats("O") | Out-File -FilePath $lastLogDateFile -Force -NoNewline
    
    # scrape outbound spam tracking logs
    #$spamTrace = Get-MailDetailSpamReport -StartDate $inceptionDate -EndDate $date -Direction outbound | Select MessageTraceID,Received,*Address,*IP,Subject,Status,Size,MessageID | Sort-Object Received
    #$messageTrace | Export-Csv $spamTraceLog -NoTypeInformation -Append

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

$traceSize = Get-Item $traceLog
if ($traceSize.Length -gt 49MB ) {
    Start-Sleep -Seconds 30
    Reset-Log -fileName $traceLog -filesize 50mb -logcount 10
}
#Reset-Log -fileName $spamTraceLog -filesize 25mb -logcount 10

# Kill Office365 Session and Clear Variables
Remove-PSSession $Session
Get-Variable -Exclude Session,banner | Remove-Variable -EA 0
