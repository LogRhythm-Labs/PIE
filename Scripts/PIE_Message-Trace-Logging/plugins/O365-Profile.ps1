  #====================================#
  #         O365 Profile               #
  # LogRhythm Security Operations      #
  # greg . foss @ logrhythm . com      #
  # v0.1  --  May, 2017                #
  #====================================#

# Copyright 2017 LogRhythm Inc.   
# Licensed under the MIT License. See LICENSE file in the project root for full license information.


<#

INSTALL:

    Import The Module or add the following line to your PowerShell profile file
		PS C:\> Import-Module .\O365-Profile.ps1

USAGE:

    Use this for easy mail authentication and message extraction
			
        Authentication:
        PS C:\> o365Auth

        Mail Extraction:
        PS C:\> get-mail -username <target.user> -sender <spammer> -socMailbox <phishin@company.com>

        Mail Quarantine:
        PS C:\> get-mail -username <target.user> -sender <spammer> -socMailbox <phishin@company.com> -nuke

        Mail Quarantine in the past:
        PS C:\> get-mail -username <target.user> -sender <spammer> -socMailbox <phishin@company.com> -nuke -past 10-20-2017

#>

# Office 365 Authentication
function o365Auth {
    param( [string]$username,
           [string]$password )
    
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
    echo ""
    echo ""
    echo "and boom goes the dynamite..."
    Clear-Variable username
    Clear-Variable password
}

# Extract Mail
function get-mail {
    param( [string]$userName,
           [string]$subject,
           [string]$sender,
           [string]$recipient,
           [string]$socMailbox,
           [string]$past,
           [switch]$nuke = $false )
    if ( $past ) {
        $day = $past
    } else {
        $day = "{0:MM-dd-yyyy}" -f (Get-Date).ToUniversalTime()
    }

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
        $searchMailboxResults = Search-Mailbox $userName -SearchQuery $messageQuery -TargetMailbox $socMailbox -TargetFolder "PROCESSING" -DeleteContent -Force
    } else {
        $searchMailboxResults = Search-Mailbox $userName -SearchQuery $messageQuery -TargetMailbox $socMailbox -TargetFolder "PROCESSING" -LogLevel Full
    }
    $searchMailboxResults
    Clear-Variable day
    Clear-Variable past
    Clear-Variable userName
    Clear-Variable subject
    Clear-Variable sender
    Clear-Variable recipient
    Clear-Variable SearchMailboxResults
}

