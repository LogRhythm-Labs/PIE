<#

LogRhythm Engineering
matt . willems [at] logrhythm.com

# Copyright 2017 LogRhythm Inc.   
# Licensed under the MIT License. See LICENSE file in the project root for full license information.

Usage:
lrcase.ps1 -lrhost <host:port> -command <command> <arg1> <arg2>

Commands:
    create_case -priority <1-5> -note <case title>
    add_note -casenum <case ID> -note <note to add>
    incident -casenum <case ID>
#>

[CmdLetBinding()]
param(

    [Parameter(Mandatory=$True)] [string]$lrhost,
    [Parameter(Mandatory=$True)] [string]$command,
    [int]$casenum,
    [string]$note,
    [string]$summary,
    [int]$priority,
    [Parameter(Mandatory=$True)] [string]$token,
    [string]$collaborator,
    [string]$owner
)

$caseFolder = "C:\PIE_INSTALL_FOLDER\plugins"

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

#Get the date/time
$date = Get-Date

#Arguments
Write-Host "Host: $lrhost"
Write-Host "Cmd: $command"

function get_case{
    param ( [int]$casenum)
    Write-Host "Get Case: URL: $geturl"
    $geturl = $caseurl + "number/$casenum"
    #execute curl POST to auth url with creds (see above)
    $output = Invoke-RestMethod -Method GET -Headers $headers -Uri $geturl 

    $caseid = $output.id
    Write-Host "Case ID: $caseid"
return $caseid
}

function create_case{
    param( [string]$name, [int]$priority)
    Write-Host "Create Case."
    Write-Host "URL:: $caseURL"
    Write-Host "Name: $name"
    Write-Host "Pri:: $priority"
    Write-Host "Summary:: $summary"

    $payload = "{ `"name`": `"$name`", `"priority`": $priority, `"summary`": `"$summary`" }"
    $output = Invoke-RestMethod -uri $caseurl -headers $headers -Method POST -body $payload

    $caseid = $output.number
return $caseid
echo $caseid > "$caseFolder\case.txt"
}

function make_folder{
    param ( [int]$casenum)

    $arm = "C:\Program Files\LogRhythm\LogRhythm Alarming and Response Manager"
    $casedir = $arm + "\case"
    if (Test-Path $casedir) {
        Write-Host "Case root path exists."
        }
    else{
        Write-Host "Case path does not exist."
        New-Item $casedir -type Directory
        }
    $casedir = $casedir + "\" + $casenum
    Try {
        New-Item $casedir -type Directory
        }
    Catch {
        Write-Error "Unable to create case path"
        Break
        }

return $casedir
}

function add_note{
    param([int]$casenum, [string]$note)

    $noteurl = $caseurl + "number/$casenum/evidence/note"
    Write-Host "Note URL: $noteurl"

    $payload = "{ `"text`": `"$note`" }"
    Write-Host "Json: $payload"

    Invoke-RestMethod -uri $noteurl -headers $headers -Method POST -body $payload

return
}

function incident{
    param([int]$casenum)

    $caseid = get_case $casenum

    $incidenturl = $caseurl + $caseid + "/actions/changeStatus"

    Write-Host "URL: $incidenturl"
    $payload = '{ "statusName": "Incident" }'

    Invoke-RestMethod -uri $incidenturl -headers $headers -Method PUT -body $payload

return
}

function add_collaborator{
    param([int]$casenum)

    $caseid = get_case $casenum

    $incidenturl = $caseurl + $caseid + "/actions/addCollaborators"

    Write-Host "Adding collaborator: $collaborator"
    $payload = "{ `"numbers`": `[$collaborator`] }"

    Invoke-RestMethod -uri $incidenturl -headers $headers -Method PUT -body $payload

return
}

function set_owner{
    param([int]$casenum)

    $caseid = get_case $casenum

    $incidenturl = $caseurl + $caseid + "/actions/changeOwner"

    Write-Host "Setting case owner: $owner"
    $payload = "{ `"number`": $owner }"

    Invoke-RestMethod -uri $incidenturl -headers $headers -Method PUT -body $payload

return
}

$token = "Bearer $token"
$caseURL = "https://$lrhost/lr-case-api/cases/"

$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-type", "application/json")
$headers.Add("Authorization", $token)

if($command -eq "create_case"){
    if ($priority -eq 0 -or $note -eq ""){
        Write-Error "Priority and note must be set."
        exit 0
        }
    elseif ($priority -ne 0 -and $note -ne ""){
        Write-Host "Creating a new case."
        $casenum = create_case $note $priority
        Write-Host "Case ID: $casenum"
        $casedir = make_folder $casenum
        Write-Host "Case Directory: $casedir"
        echo $casenum > "$caseFolder\case.txt"
        exit 1
        }
    }
elseif($command -eq "add_note"){
    if ($casenum -eq 0 -or $note -eq "") {
        Write-Error "Case Number/ID and Note must be set."
        exit 1
        }
    elseif ($casenum -ne 0 -and $note -ne ""){
        Write-Host "Adding note to case."
        add_note $casenum $note
        exit 0
        }
    }
elseif($command -eq "incident"){
    if ($casenum -eq 0){
        Write-Error "Please specify case id."
        exit 1
        }
    elseif ($casenum -ne 0){
        Write-Host "Marking case $casenum as incident"
        incident $casenum
        exit 0
        }
    }
elseif($command -eq "add_collaborator"){
    if ($casenum -eq 0){
        Write-Error "Please specify case id."
        exit 1
        }
    elseif ($casenum -ne 0 -and $collaborator -ne ""){
        Write-Host "Adding collaborators for case $casenum"
        add_collaborator $casenum
        exit 0
        }
    }
elseif($command -eq "set_owner"){
    if ($casenum -eq 0){
        Write-Error "Please specify case id."
        exit 1
        }
    elseif ($casenum -ne 0 -and $owner -ne ""){
        Write-Host "Setting case owner for case $casenum"
        set_owner $casenum
        exit 0
        }
    }
else{
    Write-Error "Unknown command. Try create_case or add_note"
    exit 0
    }