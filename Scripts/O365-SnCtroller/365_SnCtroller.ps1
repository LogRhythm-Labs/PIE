#=========================================================#
#      365 Security and Compliance Controller             #
#                   Version 1.0                           #
#                  Author: Jtekt                          #
#                 December 13 2018                        #
#=========================================================#
#
# Licensed under the MIT License. See LICENSE file in the project root for full license information.
#
#   
#
[CmdLetBinding()]
param( 
    [Parameter(Mandatory=$true,Position=1)][string]$id,
    [Parameter(Mandatory=$false,Position=2)][string]$sender,
    [Parameter(Mandatory=$false,Position=3)][string]$recipient,
    [Parameter(Mandatory=$false,Position=4)][string]$subject,
    [Parameter(Mandatory=$false,Position=5)][string]$attachmentName,
    [Parameter(Mandatory=$false,Position=6)][string]$command,
    [Parameter(Mandatory=$false,Position=7)][string]$username,
    [Parameter(Mandatory=$false,Position=8)][string]$password
)
# Mask errors
$ErrorActionPreference= 'continue'

try {
    if (-Not ($password)) {
        $cred = Get-Credential
    } Else {
        $securePass = ConvertTo-SecureString -string $password -AsPlainText -Force
        $cred = New-Object -typename System.Management.Automation.PSCredential -argumentlist $username, $securePass
    }
    $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://ps.compliance.protection.outlook.com/powershell-liveid/ -Credential $cred -Authentication Basic -AllowRedirection
    Import-PSSession $Session -AllowClobber > $null
} Catch {
    Write-Host "Access Denied..."
    Write-Host $_
    break;
}


function Purge{
[CmdLetBinding()]
param( 
    [Parameter(Mandatory=$true,Position=1)][string]$uid 
)
    $status += "Initiating 365 S&C Purge for UID: $uid."
    New-ComplianceSearchAction -SearchName "$uid" -Purge -PurgeType SoftDelete -Confirm:$false
    $purgeStatus = Get-ComplianceSearchAction -Identity "$uid`_Purge"
    DO {
        sleep 4
        Write-Host "Job: $($purgeStatus.Name) Status: $($purgeStatus.Status)"
        $purgeStatus = Get-ComplianceSearchAction -Identity "$uid`_Purge"
        if ( $purgeStatus -eq $null) {
            $purgeStatus = "Failed"
        }
    } Until (($purgeStatus.Status -eq "Completed") -xor ($purgeStatus -eq "Failed") )
    if ($purgeStatus.Status -eq "Completed") {
        $status += "Purge Status\r\nName: $($purgeStatus.Name)\r\nAction: $($purgeStatus.Action)\r\nRunBy: $($purgeStatus.RunBy)\r\nStatus: $($purgeStatus.Status)\r\nEnd Time: $($purgeStatus.JobEndTime)"
    }
    if ($purgeStatus -eq "Failed") {
        $status += "\r\nPurge Command failed."
    }
    return "$status"
}

function Search{
[CmdLetBinding()]
param( 
    [Parameter(Mandatory=$true,Position=1)][string]$uid,
    [Parameter(Mandatory=$false,Position=2)][string]$funcSender,
    [Parameter(Mandatory=$false,Position=3)][string]$funcRecipient,
    [Parameter(Mandatory=$false,Position=4)][string]$funcSubject,
    [Parameter(Mandatory=$false,Position=5)][string]$funcAttach
)
    $status += "Creating compliance search for $uid"
    if ( $funcSender -AND $funcRecipient -AND $funcSubject -AND $funcAttach ) {

        New-ComplianceSearch -name "$uid" -Description "LogRhythm SR $uid" -ContentMatchQuery "(from:$funcSender AND to:$funcRecipient AND subject=`"$funcSubject`" AND attachmentnames:$funcAttach)" -ExchangeLocation "All" -force

    } elseif ( $funcSender -AND $funcRecipient -AND $funcSubject ) {

        New-ComplianceSearch -name "$uid" -Description "LogRhythm SR $uid" -ContentMatchQuery "(from:$funcSender AND to:$funcRecipient AND subject=`"$funcSubject`")" -ExchangeLocation "All" -force

    } elseif ( $funcSender -AND $funcSubject -AND $funcAttach ) {

        New-ComplianceSearch -name "$uid" -Description "LogRhythm SR $uid" -ContentMatchQuery "(from:$funcSender AND subject=`"$funcSubject`" AND attachmentnames:$funcAttach)" -ExchangeLocation "All" -force

    } elseif ( $funcRecipient -AND $funcSubject -AND $funcAttach ) {

        New-ComplianceSearch -name "$uid" -Description "LogRhythm SR $uid" -ContentMatchQuery "(to:$funcRecipient AND subject=`"$funcSubject`" AND attachmentnames:$funcAttach)" -ExchangeLocation "All" -force

    } elseif ( $funcSender -AND $funcSubject ) {

        New-ComplianceSearch -name "$uid" -Description "LogRhythm SR $uid" -ContentMatchQuery "(from:$funcSender AND subject=`"$funcSubject`")" -ExchangeLocation "All" -force

    } elseif ( $funcRecipient -AND $funcSubject )  {

        New-ComplianceSearch -name "$uid" -Description "LogRhythm SR $uid" -ContentMatchQuery "(to:`funcRecipient AND subject=`"$funcSubject`")" -ExchangeLocation "All" -force

    } elseif ( $funcRecipient -AND $funcSender  )  {

        New-ComplianceSearch -name "$uid" -Description "LogRhythm SR $uid" -ContentMatchQuery "(to:$funcRecipient AND from:$funcSender)" -ExchangeLocation "All" -force

    } elseif ( $funcSender -AND $funcAttach )  {

        New-ComplianceSearch -name "$uid" -Description "LogRhythm SR $uid" -ContentMatchQuery "(from:$funcSender AND attachmentnames:$funcAttach)" -ExchangeLocation "All" -force

    } elseif ( $funcRecipient -AND $funcAttach )  {

        New-ComplianceSearch -name "$uid" -Description "LogRhythm SR $uid" -ContentMatchQuery "(to:$funcRecipient AND attachmentnames:$funcAttach)" -ExchangeLocation "All" -force

    } elseif ( $funcSubject -AND $funcAttach )  {

        New-ComplianceSearch -name "$uid" -Description "LogRhythm SR $uid" -ContentMatchQuery "(subject=`"$funcSubject`" AND attachmentnames:$funcAttach)" -ExchangeLocation "All" -force

    } elseif ( $funcSender  )  {

        New-ComplianceSearch -name "$uid" -Description "LogRhythm SR $uid" -ContentMatchQuery "(from:`"$funcSender`")" -ExchangeLocation "All" -force

    } elseif ( $funcSubject  )  {

        New-ComplianceSearch -name "$uid" -Description "LogRhythm SR $uid" -ContentMatchQuery "(subject=`"$funcSubject`")" -ExchangeLocation "All" -force

    } elseif ( $funcAttach ) {

        New-ComplianceSearch -name "$uid" -Description "LogRhythm SR $uid" -ContentMatchQuery "(attachmentnames:$funcAttach)" -ExchangeLocation "All" -force

    } else {

        Write-Host "No critera"

    }

    $status += "Starting compliance search."
    Start-ComplianceSearch -Identity "$uid"
    #Start on returning audit search results
    $p1 = Get-ComplianceSearch -Identity "$uid"
    DO {
        sleep 15
        Write-Host "Job: $($p1.Name) Status: $($p1.Status)"
        $p1 = Get-ComplianceSearch -Identity "$uid"
        if ( $p1 -eq $null) {
            $p1 = "Failed"
        }
    } Until ( ($p1.Status -eq "Completed" ) -xor ($p1 -eq "Failed") )
    if ($($p1.Status) -eq "Completed") {
        $status += "Purge Status\r\nName: $($p1.Name)"
        $status += "Compliance search complete.\r\nTo access results go to: https://protection.office.com/"
    }
    if ($p1 -eq "Failed") {
        $status += "\r\nSearch Command failed."
    }
}


if ( $sender -OR $recipient -OR $subject -OR $attachmentName ) {
    #Search
    if ( $command -eq "Search" ) {
       Write-Host "ID: $id Sender: $sender Recipient: $recipient Subject: $subject Attachment: $attachmentName"
       $sdStatus = Search -uid $id -funcSender $sender -funcRecipient $recipient -funcSubject $subject -funcAttach $attachmentName
    }
    #Search and Purge
    if ( $command -eq "SnP" ) {
       $sdStatus = Search -uid $id -funcSender $sender -funcRecipient $recipient -funcSubject $subject -funcAttach $attachmentName
       $pgStatus = Purge -uid $id
    }
} elseif ( $command -eq "Purge" -And $id ) {
    #Purge
    $pgStatus = Purge -uid $id
} else {
    Write-Host "Please provide a search criteria."
    Remove-PSSession $Session
    Exit 1
}
Remove-PSSession $Session
Exit 0