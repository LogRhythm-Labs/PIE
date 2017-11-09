
  #====================================#
  # SPAM Tracker - Add Item to List    #
  # LogRhythm Security Operations      #
  # greg . foss @ logrhythm . com      #
  # v1.0  --  November, 2017           #
  #====================================#

# Copyright 2017 LogRhythm Inc.   
# Licensed under the MIT License. See LICENSE file in the project root for full license information.

<#

USAGE:

    Install the Module:
        PS C:\> Import-Module . .\Spam-Tracker.ps1

    Run the Module:
        PS C:\> Spam-Tracker <email> -case <case number> -caseAPItoken <key> -spammerList <\\share\location\file.txt>

#>

# ================================================================================
# Add Spammer to Threat List
# ================================================================================

function spam-tracker {

    param ( [string]$email = $_,
            [string]$case,
            [string]$LogRhythmHost,
            [string]$caseAPItoken,
            [string]$spammerList )

    $regexCheck="[a-z0-9!#\$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#\$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
    
    if ( $email -match $regexCheck ) {
        Write-Output "$email" >> $spammerList
        Write-Host ""
        Write-Host "Email address ($email) added to Threat List ($spammerList)"
        Write-Host ""
        if ( $case ) {
            $caseStatus = "Email address ($email) added to the known-spammers threat list"
        
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
        
            # Update Case status
            $noteurl = $caseURL + "number/$case/evidence/note"
            Write-Host "Adding Case Note: $noteurl"
            $payload = "{ `"text`": `"$caseStatus`" }"
            Write-Host "Json: $payload"
            Invoke-RestMethod -uri $noteurl -headers $headers -Method POST -body $payload

        }

    } else {
        Write-Host ""
        Write-Host "Error: I require a proper email address..."
        Write-Host ""
    }
    Clear-Variable email
    Clear-Variable case
    Clear-Variable LogRhythmHost
    Clear-Variable caseAPItoken
    Clear-Variable spammerList
    Clear-Variable regexCheck

}