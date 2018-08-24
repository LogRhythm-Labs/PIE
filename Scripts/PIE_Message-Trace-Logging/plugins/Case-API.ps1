
#====================================#
#       Case API - 7.3.x             #
# LogRhythm Security Operations      #
# greg . foss @ logrhythm . com      #
# v1.0  --  August, 2018             #
#====================================#

# Copyright 2018 LogRhythm Inc.   
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
        [switch]$listTags )


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


# ================================================================================
# Situational Awareness
# ================================================================================

#Get the date/time
$date = Get-Date

# Get Case Information
if ( $getCases ) {
    $output = Invoke-RestMethod -Uri $caseURL -Headers $headers -Method GET
    $output | Select-Object * | Out-GridView
}

# Get List of Available Tags
if ( $listTags ) {
    $tagUrl = "https://$lrhost/lr-case-api/tags/"
    $output = Invoke-RestMethod -Uri $tagUrl -Headers $headers -Method GET
    $output | Sort-Object number | Out-GridView
}


# ================================================================================
# Create Case
# ================================================================================    

if ($createCase ) {

    # REST Web Request
    $payload = "{ `"name`": `"$createCase`", `"priority`": $priority, `"summary`": `"$summary`" }"
    $output = Invoke-RestMethod -Uri $caseURL -Headers $headers -Method POST -Body $payload
        
    # Capture Case ID for Later Usage
    $caseNum = $output.number
        
    echo $caseNum > "$caseFolder\case.txt"
}


# ================================================================================
# Update Case
# ================================================================================

if ( $updateCase ) {
    if ( $caseNum ) {

        # Update the Case
        $noteurl = $caseurl + "/number/$caseNum/evidence/note"

        # REST Web Request
        $payload = "{ `"text`": `"$updateCase`" }"
        $output = Invoke-RestMethod -Uri $noteurl -Headers $headers -Method POST -Body $payload
    }
}


# ================================================================================
# Add Tags
# ================================================================================

if ( $addTag ) {
    if ( $caseNum ) {

        # Find Tag
        $tagUrl = "https://$lrhost/lr-case-api/tags/"
        $output = Invoke-RestMethod -Uri $tagUrl -Headers $headers -Method GET
        $tagNumber = @($output | Select-Object number, text | Where-Object text -EQ "$addTag").number

        if ( $tagNumber ) {

             # Find Case UUID
            $output = Invoke-RestMethod -Uri $caseURL -Headers $headers -Method GET
            $output2 = $output | Select-Object number, id | Where-Object number -EQ $caseNum
            $caseUUID = $output2.id

            # Tag the case
            $tagUrl = $caseUrl + "/$caseUUID/actions/addTags"

            # REST Web Request
            $payload = "{ `"numbers`": `[$tagNumber`] }"
            $output = Invoke-RestMethod -Uri $tagUrl -Headers $headers -Method PUT -Body $payload

        }       
    }
}


# ================================================================================
# Remove Tags
# ================================================================================

if ( $removeTag ) {
    if ( $caseNumber ) {
                
        # Find Tag
        $tagUrl = "https://$lrhost/lr-case-api/tags/"
        $output = Invoke-RestMethod -Uri $tagUrl -Headers $headers -Method GET
        $tagNumber = @($output | Select-Object number, text | Where-Object text -EQ "$removeTag").number
            
        if ( $tagNumber ) {
            
            # Find Case UUID
            $output = Invoke-RestMethod -Uri $caseURL -Headers $headers -Method GET
            $output = $output | Select-Object number, id | Where-Object number -EQ $caseNumber
            $caseUUID = $output.id

            # Tag the case
            $tagUrl = $caseUrl + "/$caseUUID/actions/removeTags"

            # REST Web Request
            $payload = "{ `"numbers`": `[$tagNumber`] }"
            $output = Invoke-RestMethod -Uri $tagUrl -Headers $headers -Method PUT -Body $payload

        }
    }
}

# ================================================================================
# Add User to Case
# ================================================================================

if ( $addCaseUser ) {
    if ( $caseNum ) {

        # User Lookup
        $userLookup = "https://$lrhost/lr-case-api/persons/"
        $output = Invoke-RestMethod -Uri $userLookup -Headers $headers -Method GET
        $userNumber = @($output | Where-Object name -eq "$addCaseUser" | Select-Object number).number

        # Find Case UUID
        $output = Invoke-RestMethod -Uri $caseURL -Headers $headers -Method GET
        $output = $output | Select-Object number, id | Where-Object number -EQ $caseNum
        $caseUUID = $output.id

        # Add Case User
        $userQuery = $caseURL + "/$caseUUID/actions/addCollaborators/"

        # REST Web Request
        $payload = "{ `"numbers`": `[$userNumber`] }"
        $output = Invoke-RestMethod -Uri $userQuery -Headers $headers -Method PUT -Body $payload

    }
}


# ================================================================================
# Remove User From Case
# ================================================================================

if ( $removeCaseUser ) {
    if ( $caseNum ) {

        # User Lookup
        $userLookup = "https://$lrhost/lr-case-api/persons/"
        $output = Invoke-RestMethod -Uri $userLookup -Headers $headers -Method GET
        $userNumber = @($output | Where-Object name -eq "$removeCaseUser" | Select-Object number).number
            
        # Find Case UUID
        $output = Invoke-RestMethod -Uri $caseURL -Headers $headers -Method GET
        $output = $output | Select-Object number, id | Where-Object number -EQ $caseNum
        $caseUUID = $output.id

        # Add Case User
        $userQuery = $caseURL + "/$caseUUID/actions/removeCollaborators/"

        # REST Web Request
        $payload = "{ `"numbers`": `[$userNumber`] }"
        $output = Invoke-RestMethod -Uri $userQuery -Headers $headers -Method PUT -Body $payload
        
    }
}

    
# ================================================================================
# Change Case Owner
# ================================================================================

if ( $changeCaseOwner ) {
    if ( $caseNum ) {

        # User Lookup
        $userLookup = "https://$lrhost/lr-case-api/persons/"
        $output = Invoke-RestMethod -Uri $userLookup -Headers $headers -Method GET
        $userNumber = @($output | Where-Object name -eq "$changeCaseOwner" | Select-Object number).number
            
        # Find Case UUID
        $output = Invoke-RestMethod -Uri $caseURL -Headers $headers -Method GET
        $output = $output | Select-Object number, id | Where-Object number -EQ $caseNum
        $caseUUID = $output.id

        # Add Case User
        $userUpdate = $caseURL + "/$caseUUID/actions/changeOwner/"

        # REST Web Request
        $payload = "{ `"number`": $userNumber }"
        $output = Invoke-RestMethod -Uri $userUpdate -Headers $headers -Method PUT -Body $payload
        
    }
}


# ================================================================================
# Attach File ----- CURRENTLY BROKEN -----
# ================================================================================

if ( $attachFile ) {
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
