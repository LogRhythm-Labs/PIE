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
$threatScore = 0

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
$malware = $urlscanResults.stats.malicious
$certIssuers = $urlscanResults.lists.certificates.issuer
$domains = $urlscanResults.lists.domains
$serverStats = $urlscanResults.stats.serverStats.Count
#Hosted file info
$filename = $urlscanResults.meta.processors.download.data.filename
$fileHash = $urlscanResults.meta.processors.download.data.sha256
$fileSize = $urlscanResults.meta.processors.download.data.filesize
$fileMimeType = $urlscanResults.meta.processors.download.data.mimeType
$fileMimeDesc = $urlscanResults.meta.processors.download.data.mimeDescription

#Build display info
$status = "====INFO - URLSCAN====\r\nScanned Link`: $link"
if ( $serverStats -eq 0 ) {
    $status += "\r\nALERT: Website could not be scanned by urlscan.io\r\nScans from urlscan.io are based from Germany.  \r\nPossible geographical-ip or explicit urlscan.io blocked."
} else {
    $status += "\r\n\r\nScan Report`: $repURL"
    if ( $filename -ne $null ) {
        $status += "\r\nFile name: $filename\r\nSha256 hash: $fileHash\r\nFile size: $fileSize\r\nMIME Type: $fileMimeType\r\nMIME Description: $fileMimeDesc"
        $dlHshPath = "$caseFolder\$caseID\urlScan"
        if (!(Test-Path -Path $dlHshPath)) {
            New-Item -Path $dlHshPath -ItemType directory
        }
        echo "$fileHash,$filename" >> "$dlHshPath/hashes.txt"
        #$status += "\r\n\r\nFile Path: "+$networkShare+"urlScan\hashes.txt"

    } else {
        $status += "\r\nURL Screenshot`: $ssURL"
		#Download copy of destination link
		if ( $downloadPNG -eq $true ) {
			$dlFilename = $scannedURL | %{ ([System.Uri]$_).Host }
			$dlFilename = $dlFilename -replace "www.",""
			$dlFilename = "$dlFilename.uid-$($ssURL.Split("/")[4])"
            $dlSCPath = "$caseFolder\$caseID\urlScan\"
            if (!(Test-Path -Path $dlSCPath)) {
                New-Item -Path $dlSCPath -ItemType directory
            }
			$dlSCFull = "$dlSCPath$dlFilename"
			Invoke-WebRequest -Uri $ssURL -OutFile $dlSCFull
		}
    }   
}
if ($malware -gt 0 ) {
    $status += "\r\nALERT: Malware reported!"
	$threatScore += 1
}
if ( $certIssuers -imatch "Let's Encrypt" ) {
    $status += "\r\nALERT: Let's Encrypt Certificate Authority Detected!"
}
if ( $certIssuers -imatch $domains ) {
    $status += "\r\nALERT: Self-Signed Certificate Detected!"
	$threatScore += 1   	
}

$status += "\r\n\r\nScan Time: $scanTime\r\n====END - URLSCAN===="

& $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$status" -token $caseAPItoken
echo $status.Replace("\r\n","`r`n") >> "$caseFolder$caseID\spam-report.txt"