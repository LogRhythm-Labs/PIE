#
# Author: JTekt
# October 2018
# Version 0.5
#
# URLScan.io integration for PIE.  
#   
#
# .\URLScan.ps1 -key $urlscanAPI -link $splitLink -caseID $caseID -caseFolder $caseFolder -pieFolder $pieFolder -logRhythmHost $logRhythmHost -caseAPItoken $caseAPItoken -networkShare $networkShare

[CmdLetBinding()]
param( 
    [string]$key,
    [string]$link,
    [string]$caseID,
    [string]$caseFolder,
    [string]$pieFolder,
    [string]$LogRhythmHost,
    [string]$caseAPItoken,
    [string]$networkShare
)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Mask errors
$ErrorActionPreference= 'silentlycontinue'

# Optional Parameters
#Downloads screenshot of link destination to PIE case folder
$downloadPNG = $true

#Request and load scan request results
$urlscanRequest = Invoke-WebRequest -Headers @{"API-Key" = "$key"} -Method Post ` -Body "{`"url`":`"$link`",`"public`":`"off`"}" -Uri https://urlscan.io/api/v1/scan/ ` -ContentType application/json
$urlscanRequest.RawContent | Out-File $tmpFolder\urlscanRequest.txt
$urlscanStatus = Get-Content $tmpFolder\urlscanRequest.txt | select -Skip 15 | ConvertFrom-Json

#Determine when scan has completed
DO
{
    Write-Verbose "Waiting for scan to complete"
    sleep 5
    try {
        $urlscanResultQuery = Invoke-WebRequest -Headers @{"API-Key" = "$apikey"} -Method Get ` -Uri $($urlscanStatus.api) ` -ContentType application/json
        $status = "200"
    } catch {
    $status =$_.Exception.Response.StatusCode.Value__
    }
} While ($status -eq "404" )

#Load scan results and populate variables
#This could be built out to retrieve additional information from the scan results.
$urlscanResultQuery.RawContent | Out-File $tmpFolder\urlscanAnalysis.txt
$urlscanResults = Get-Content $tmpFolder\urlscanAnalysis.txt | select -Skip 15 | ConvertFrom-Json
$scanTime = $urlscanResults.task.time
$scannedURL = $urlscanResults.task.url
$ssURL = $urlscanResults.task.screenshotURL
$repURL = $urlscanResults.task.reportURL

$status = "====INFO - URLSCAN====\r\nScanned Link`: $link\r\nScan Report`: $repURL\r\nURL Screenshot`: $ssURL"

#Download copy of destination link
if ( $downloadPNG -eq $true ) {
    $filename = $scannedURL | %{ ([System.Uri]$_).Host }
    $filename = $filename -replace "www.",""
    $filename = "$filename.uid-$($ssURL.Split("/")[4])"
    $dlPath = "$caseFolder\$caseID\$filename"
    Invoke-WebRequest -Uri $ssURL -OutFile $dlPath
    $status += "\r\nLocation: $networkShare$filename"
}
$status += "\r\n\r\nScan Time: $scanTime\r\n****END - URLSCAN ****"

& $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$status" -token $caseAPItoken
echo $status.Replace("\r\n","`r`n") >> "$caseFolder$caseID\spam-report.txt"