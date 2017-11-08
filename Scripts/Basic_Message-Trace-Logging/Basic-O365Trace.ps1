
  #====================================#
  # PIE - Phishing Intelligence Engine #
  # LogRhythm Security Operations      #
  # greg . foss @ logrhythm . com      #
  # v1.0  --  October, 2017            #
  #====================================#

# Copyright 2017 LogRhythm Inc.   
# Licensed under the MIT License. See LICENSE file in the project root for full license information.

<#

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


# ================================================================================
# DEFINE GLOBAL PARAMETERS AND CAPTURE CREDENTIALS
# ================================================================================

# Mask errors
$ErrorActionPreference= 'silentlycontinue'

# Office 365 Connectivity
$username = "USERNAME HERE"
$password = "PASSWORD HERE"

# Case Folders and Logging
$logFolder = "C:\PIE-INSTALL-DIRECTORY"
$traceLog = "$logFolder\logs\ongoing-trace-log.csv"
$log = $true


# ================================================================================
# DATE, FILE, AND GLOBAL EMAIL PARSING
# ================================================================================

# Date Variables
$date = Get-Date
$oldAF = (Get-Date).AddDays(-10)
$48Hours = (Get-Date).AddHours(-48)
$24Hours = (Get-Date).AddHours(-24)
$inceptionDate = (Get-Date).AddMinutes(-6)
$phishDate = (Get-Date).AddMinutes(-7)
$day = Get-Date -Format MM-dd-yyyy


# ================================================================================
# Office 365 API Authentication
# ================================================================================

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

    # scrape all mail - ongiong log generation
    $messageTrace = Get-MessageTrace -StartDate $inceptionDate -EndDate $date | Select MessageTraceID,Received,*Address,*IP,Subject,Status,Size,MessageID | Sort-Object Received
    $messageTrace | Export-Csv $traceLog -NoTypeInformation -Append
    
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
 
Reset-Log -fileName $traceLog -filesize 50mb -logcount 10
#Reset-Log -fileName $spamTraceLog -filesize 25mb -logcount 10

# Kill Office365 Session and Clear Variables
Remove-PSSession $Session
Get-Variable -Exclude Session,banner | Remove-Variable -EA 0
