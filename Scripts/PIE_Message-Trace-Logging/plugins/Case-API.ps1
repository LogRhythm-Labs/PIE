
#====================================#
#       Case API - 7.4.x             #
# LogRhythm Security Operations      #
# v1.5  --  June, 2019               #
#====================================#

# Copyright 2019 LogRhythm Inc.   
# Licensed under the MIT License. See LICENSE file in the project root for full license information.

# ================================================================================
# LogRhythm Case Management
# ================================================================================

param ( [string]$lrhost,
        [string]$token,
        [string]$summary,
        [string]$createCase,
        [string]$updateCase,
        [string]$addTag,
        [string]$removeTag,
        [string]$addCaseUser,
        [string]$removeCaseUser,
        [string]$changeCaseOwner,
        [string]$attachFile,
        [string]$note,
        [string]$tagNumber,
        [string]$caseNum,
        [string]$priority,
        [switch]$getCases,
        [switch]$listTags,
        [string]$addPlaybook,
        [string]$runLog,
        [string]$pluginLogLevel )


# ================================================================================
# EDIT THE CASE FOLDER LINE BELOW
# ================================================================================

$caseFolder = "C:\PIE\Install\Directory\plugins"

##################################################################################


# ================================================================================
# Global Parameters
# ================================================================================

# Mask errors
$ErrorActionPreference= 'silentlycontinue'

$apiKey = "Bearer $token"
$caseURL = "https://$lrhost/lr-case-api/cases"
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-type", "application/json")
$headers.Add("Authorization", $apiKey)
$headers.Add("Count", "100000")
    
if (-Not ($summary)) { $summary = "API Generated Case" }
if (-Not ($priority)) { $priority = "3" }

#force TLS v1.2 required by caseAPI
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#Ignore invalid SSL certification warning
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

function Logger {
    Param(
        $logLevel = $pluginLogLevel,
        $logSev,
        $Message
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
}

# ================================================================================
# Situational Awareness
# ================================================================================

#Get the date/time
$date = Get-Date

# Get Case Information
if ( $getCases ) {
    Logger -logSev "i" -Message "Plugin Case-API - Begin Get Case"
    $output = Invoke-RestMethod -Uri $caseURL -Headers $headers -Method GET
    $output | Select-Object * | Out-GridView
    Logger -logSev "i" -Message "Plugin Case-API - End Get Case"
}

# Get List of Available Tags
if ( $listTags ) {
    Logger -logSev "i" -Message "Plugin Case-API - Begin List Tags"
    $tagUrl = "https://$lrhost/lr-case-api/tags/"
    $output = Invoke-RestMethod -Uri $tagUrl -Headers $headers -Method GET
    $output | Sort-Object number | Out-GridView
    Logger -logSev "i" -Message "Plugin Case-API - End List Tags"
}


# ================================================================================
# Create Case
# ================================================================================    

if ($createCase ) {
    Logger -logSev "i" -Message "Plugin Case-API - Begin Create Case"

    # REST Web Request
    Logger -logSev "d" -Message "Plugin Case-API - Submitting Case Creation"
    $payload = "{ `"name`": `"$createCase`", `"priority`": $priority, `"summary`": `"$summary`" }"
    $output = Invoke-RestMethod -Uri $caseURL -Headers $headers -Method POST -Body $payload
        
    # Capture Case ID for Later Usage
    $caseNum = $output.number
    Logger -logSev "d" -Message "Plugin Case-API - Returned Case ID $caseNum"
    Try {
        Logger -logSev "d" -Message "Plugin Case-API - Writing $caseNum to $caseFolder\case.txt"
        echo $caseNum > "$caseFolder\case.txt"
        }
    Catch {
        Logger -logSev "e" -Message "Plugin Case-API - Unable to write to $caseFolder\case.txt"
    }
    Logger -logSev "i" -Message "Plugin Case-API - End Create Case"
}


# ================================================================================
# Update Case
# ================================================================================

if ( $updateCase ) {
    Logger -logSev "i" -Message "Plugin Case-API - Begin Update Case"
    if ( $caseNum ) {

        # Update the Case
        $noteurl = $caseurl + "/number/$caseNum/evidence/note"

        # REST Web Request
        Logger -logSev "d" -Message "Plugin Case-API - Submitting note to case $caseNum"
        $payload = "{ `"text`": `"$updateCase`" }"
        $output = Invoke-RestMethod -Uri $noteurl -Headers $headers -Method POST -Body $payload
    }
    Logger -logSev "i" -Message "Plugin Case-API - End Update Case"
}


# ================================================================================
# Add Tags
# ================================================================================

if ( $addTag ) {
    Logger -logSev "i" -Message "Plugin Case-API - Begin Add Tags"
    if ( $caseNum ) {

        # Find Tag
        $tagUrl = "https://$lrhost/lr-case-api/tags/"
        $output = Invoke-RestMethod -Uri $tagUrl -Headers $headers -Method GET
        $tagNumber = @($output | Select-Object number, text | Where-Object text -EQ "$addTag").number
        Logger -logSev "d" -Message "Plugin Case-API - Returned $removeTag tagID $tagNumber"

        if ( $tagNumber ) {

             # Find Case UUID
            $output = Invoke-RestMethod -Uri $caseURL -Headers $headers -Method GET
            $output2 = $output | Select-Object number, id | Where-Object number -EQ $caseNum
            $caseUUID = $output2.id
            Logger -logSev "d" -Message "Plugin Case-API - Returned caseUUID $caseUUID"

            # Tag the case
            $tagUrl = $caseUrl + "/$caseUUID/actions/addTags"

            # REST Web Request
            Logger -logSev "d" -Message "Plugin Case-API - Submitting $removeTag tagID $tagNumber to case $caseUUID"
            $payload = "{ `"numbers`": `[$tagNumber`] }"
            $output = Invoke-RestMethod -Uri $tagUrl -Headers $headers -Method PUT -Body $payload

        }       
    }
    Logger -logSev "i" -Message "Plugin Case-API - End Add Tags"
}


# ================================================================================
# Remove Tags
# ================================================================================

if ( $removeTag ) {
    Logger -logSev "i" -Message "Plugin Case-API - Begin Remove Tags"
    if ( $caseNumber ) {
                
        # Find Tag
        $tagUrl = "https://$lrhost/lr-case-api/tags/"
        $output = Invoke-RestMethod -Uri $tagUrl -Headers $headers -Method GET
        $tagNumber = @($output | Select-Object number, text | Where-Object text -EQ "$removeTag").number
        Logger -logSev "d" -Message "Plugin Case-API - Returned $removeTag tagID $tagNumber"
            
        if ( $tagNumber ) {
            
            # Find Case UUID
            $output = Invoke-RestMethod -Uri $caseURL -Headers $headers -Method GET
            $output = $output | Select-Object number, id | Where-Object number -EQ $caseNumber
            $caseUUID = $output.id
            Logger -logSev "d" -Message "Plugin Case-API - Returned caseUUID $caseUUID"

            # Tag the case
            $tagUrl = $caseUrl + "/$caseUUID/actions/removeTags"

            # REST Web Request
            Logger -logSev "d" -Message "Plugin Case-API - Submitting $removeTag tagID $tagNumber to case $caseUUID"
            $payload = "{ `"numbers`": `[$tagNumber`] }"
            $output = Invoke-RestMethod -Uri $tagUrl -Headers $headers -Method PUT -Body $payload

        }
    }
    Logger -logSev "i" -Message "Plugin Case-API - End Remove Tags"
}

# ================================================================================
# Add User to Case
# ================================================================================

if ( $addCaseUser ) {
    Logger -logSev "i" -Message "Plugin Case-API - Begin Add User to Case"
    if ( $caseNum ) {

        # User Lookup
        $userLookup = "https://$lrhost/lr-case-api/persons/"
        $output = Invoke-RestMethod -Uri $userLookup -Headers $headers -Method GET
        $userNumber = @($output | Where-Object name -eq "$addCaseUser" | Select-Object number).number
        Logger -logSev "d" -Message "Plugin Case-API - Returned userNumber $userNumber"

        # Find Case UUID
        $output = Invoke-RestMethod -Uri $caseURL -Headers $headers -Method GET
        $output = $output | Select-Object number, id | Where-Object number -EQ $caseNum
        $caseUUID = $output.id
        Logger -logSev "d" -Message "Plugin Case-API - Returned caseUUID $caseUUID"

        # Add Case User
        $userQuery = $caseURL + "/$caseUUID/actions/addCollaborators/"

        # REST Web Request
        Logger -logSev "d" -Message "Plugin Case-API - Submitting user $addCaseUser with ID $userNumber to case $caseUUID"
        $payload = "{ `"numbers`": `[$userNumber`] }"
        $output = Invoke-RestMethod -Uri $userQuery -Headers $headers -Method PUT -Body $payload

    }
    Logger -logSev "i" -Message "Plugin Case-API - End Add User to Case"
}


# ================================================================================
# Remove User From Case
# ================================================================================

if ( $removeCaseUser ) {
    Logger -logSev "i" -Message "Plugin Case-API - Begin Remove User from Case"
    if ( $caseNum ) {

        # User Lookup
        $userLookup = "https://$lrhost/lr-case-api/persons/"
        $output = Invoke-RestMethod -Uri $userLookup -Headers $headers -Method GET
        $userNumber = @($output | Where-Object name -eq "$removeCaseUser" | Select-Object number).number
        Logger -logSev "d" -Message "Plugin Case-API - Returned userNumber $userNumber"
            
        # Find Case UUID
        $output = Invoke-RestMethod -Uri $caseURL -Headers $headers -Method GET
        $output = $output | Select-Object number, id | Where-Object number -EQ $caseNum
        $caseUUID = $output.id
        Logger -logSev "d" -Message "Plugin Case-API - Returned caseUUID $caseUUID"

        # Add Case User
        $userQuery = $caseURL + "/$caseUUID/actions/removeCollaborators/"

        # REST Web Request
        Logger -logSev "d" -Message "Plugin Case-API - Submitting user $removeCaseUser with ID $userNumber to case $caseUUID"
        $payload = "{ `"numbers`": `[$userNumber`] }"
        $output = Invoke-RestMethod -Uri $userQuery -Headers $headers -Method PUT -Body $payload
        
    }
    Logger -logSev "i" -Message "Plugin Case-API - End Remove User from Case"
}

    
# ================================================================================
# Change Case Owner
# ================================================================================

if ( $changeCaseOwner ) {
    Logger -logSev "i" -Message "Plugin Case-API - Begin Change Case Owner"
    if ( $caseNum ) {

        # User Lookup
        $userLookup = "https://$lrhost/lr-case-api/persons/"
        $output = Invoke-RestMethod -Uri $userLookup -Headers $headers -Method GET
        $userNumber = @($output | Where-Object name -eq "$changeCaseOwner" | Select-Object number).number
        Logger -logSev "d" -Message "Plugin Case-API - Returned userNumber $userNumber"
            
        # Find Case UUID
        $output = Invoke-RestMethod -Uri $caseURL -Headers $headers -Method GET
        $output = $output | Select-Object number, id | Where-Object number -EQ $caseNum
        $caseUUID = $output.id
        Logger -logSev "d" -Message "Plugin Case-API - Returned caseUUID $caseUUID"

        # Add Case User
        $userUpdate = $caseURL + "/$caseUUID/actions/changeOwner/"

        # REST Web Request
        Logger -logSev "d" -Message "Plugin Case-API - Submitting user $changeCaseOwner with ID $userNumber to case $caseUUID"
        $payload = "{ `"number`": $userNumber }"
        $output = Invoke-RestMethod -Uri $userUpdate -Headers $headers -Method PUT -Body $payload
        
    }
    Logger -logSev "i" -Message "Plugin Case-API - End Change Case Owner"
}

    
# ================================================================================
# Add Playbook
# ================================================================================
if ( $addPlaybook ) {
    Logger -logSev "i" -Message "Plugin Case-API - Begin Add Playbook"
    if ( $caseNum ) {
        $noteurl = "https://$lrhost/lr-case-api/playbooks/"
        # Get Playbooks
        $playbookOutput = Invoke-RestMethod -Uri $noteurl -Headers $headers -Method GET
        $playbookID = @($playbookOutput | Where-Object name -eq "$addPlaybook" |Select-Object id).id
        Logger -logSev "d" -Message "Plugin Case-API - Returned PlaybookID $playbookID"

        # REST Web Request
        Logger -logSev "d" -Message "Plugin Case-API - Submitting playbook $playbookID to case $caseNum"
        $noteurl = "https://$lrhost/lr-case-api/cases/$caseNum/playbooks/"
        $payload = "{ `"id`": `"$playbookID`" }"
        $output = Invoke-RestMethod -Uri $noteurl -Headers $headers -Method POST -Body $payload
    }
    Logger -logSev "i" -Message "Plugin Case-API - End Add Playbook"
}



# ================================================================================
# Attach File ----- CURRENTLY BROKEN -----
# ================================================================================

if ( $attachFile ) {
    Logger -logSev "i" -Message "Plugin Case-API - Begin Attach File"
    if ( $note ) {
        if ( $caseNum ) {

            # Find Case UUID
            $output = Invoke-RestMethod -Uri $caseURL -Headers $headers -Method GET
            $output = $output | Select-Object number, id | Where-Object number -EQ $caseNum
            $caseUUID = $output.id

            # Reset Headers and Attach File
            #$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
            #$headers.Add("Content-type", "application/x-www-form-urlencoded")
            #$headers.Add("Authorization", $token)
            $attachmentUrl = $caseURL + "/$caseUUID/evidence/file"

            <#Parameters that are submitted through a form.
            application/x-www-form-urlencoded, multipart/form-data or both are usually
            used as the content type of the request#>

            $FileContent = [IO.File]::ReadAllText('C:\Users\greg.foss_sup\Desktop\scripts\test.txt');
            #$FileContent = [IO.File]::ReadAllBytes('C:\Users\greg.foss_sup\Desktop\scripts\test.txt');
            #$Fields = @{'appInfo'='{"name": "test","description": "test"}';'uploadFile'=$FileContent};

            $payload = @{"appInfo"="{ `"note`": `"$note`", `"file`": `"$fileContent`" }";'uploadFile'=$FileContent}
            #$payload = "{ `"file`": `"$FileContent`", `"note`": `"$note`" }"
            $output = Invoke-RestMethod -Uri $attachmentUrl -Headers $headers -Method POST -Body $payload -ContentType "multipart/form-data"
            
        }  
    }
    Logger -logSev "i" -Message "Plugin Case-API - End Attach File"
}


# ================================================================================
# Template
# ================================================================================

if ( $asdf ) {
    if ( $caseNum ) {

        # REST Web Request
        $payload = "{ `"text`": `"$updateCase`" }"
        $output = Invoke-RestMethod -Uri $noteurl -Headers $headers -Method POST -Body $payload
        
    }
}

# Clear all variables
Get-Variable | Remove-Variable -EA 0
