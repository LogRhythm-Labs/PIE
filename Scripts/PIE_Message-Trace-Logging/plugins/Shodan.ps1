#
# Author: JTekt
# August 2018
#
# Early development of Shodan integration for PIE.  Exploritory to identify potential areas of evidence collection and risk assessment acceleration.
#   
# Goals:
# <complete> - Collect additional evidence on link.  Geographic location, IP address, Certificate Authority & expiration.
# <complete> - Report self-signed certificates.
# <complete> - Initially groom to find LetsEncrypt Self-Registration certificates.  This may be a point to increase threatScore.
# <incomplete> Explore examination of services running on host.  Example, if identifying tor/tftp/ftp or other file delivery services found in conjuction with HTTP/HTTPS, increase threatScore.
#

# .\Shodan.ps1 -key $shodanAPI -link $splitLink -caseID $caseID -caseFolder $caseFolder -pieFolder $pieFolder -logRhythmHost $logRhythmHost -caseAPItoken $caseAPItoken

[CmdLetBinding()]
param( 
    [string]$key,
    [string]$link,
    [string]$caseID,
    [string]$caseFolder,
    [string]$pieFolder,
    [string]$LogRhythmHost,
    [string]$caseAPItoken
)

# Mask errors
$ErrorActionPreference= 'silentlycontinue'

# Global Parameters
$IPregex='(?<Address>((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))'
# Optional information.  Will append domain information into LR case.
$shodanDetails = $true

# Query DNS and obtain domain IP address
$shodanIPQuery = Invoke-RestMethod "https://api.shodan.io/dns/resolve?hostnames=$link&key=$key"
$shodanIPQuery | Where-Object -Property $link -Match $IPregex
$shodanIP = $Matches.Address
$shodanLink = "https://www.shodan.io/host/$shodanIP"

# Query Shodan Host scan
$shodanHostInfo = Invoke-RestMethod "https://api.shodan.io/shodan/host/$shodanIP`?key=$key"
$shodanScanDate = $shodanHostInfo.last_update
$shodanCountry = $shodanHostInfo.country_name
$shodanRegion = $shodanHostInfo.region_code
$shodanCity = $shodanHostInfo.city
$shodanPostal = $shodanHostInfo.postal_code
$shodanPorts = $shodanHostInfo.ports
$shodanTags = $shodanHostInfo.tags

echo "Host Information: $shodanHostInfo" >> "$caseFolder$caseID\spam-report.txt"
echo "Scan Date: $shodanScanDate" >> "$caseFolder$caseID\spam-report.txt"
echo "Country: $shodanCountry" >> "$caseFolder$caseID\spam-report.txt"
echo "Region: $shodanRegion" >> "$caseFolder$caseID\spam-report.txt"
echo "City: $shodanCity" >> "$caseFolder$caseID\spam-report.txt"
echo "Postal Code: $shodanPostal" >> "$caseFolder$caseID\spam-report.txt"
echo "Ports: $shodanPorts" >> "$caseFolder$caseID\spam-report.txt"
echo "Tags: $shodanTags" >> "$caseFolder$caseID\spam-report.txt"

#Determine if HTTPS services identified.
$shodanModules = $shodanHostInfo.data | Select-Object -ExpandProperty _shodan | Select-Object -ExpandProperty module

$shodanHostInfo

#If HTTPS identified populate associated variables.
if ( $shodanModules -imatch "https" ) {
    $shodanSSL = $true
    $shodanCert1 = $shodanHostInfo.data | Select-Object -ExpandProperty ssl
    $shodanCertIssuer = $shodanCert1.cert.issuer.CN
    $shodanCertExpiration = $shodanCert1.cert.expires

    echo $shodanCert1 > "$caseFolder$caseID\Link-$link-Certificate.txt"
       
} else {

    Write-Host "Scanned host does not run any HTTPS services."
    $shodanSSL = $false
    $shodanCert1 = $null
    $shodanCertIssuer = $null
    $shodanCertExpiration = $null
}

if ( $shodanCert1.cert.expired -eq $true ) {
    $shodanStatus = "EXPIRED CERTIFICATE! Shodan has reported $link has expired certificates. Last scanned on $shodanScanDate.  Full details available here: $shodanLink."
    Write-Host $shodanStatus
    $threatScore += 1

    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -command add_note -casenum $caseNumber -note "$shodanStatus" -token $caseAPItoken
    echo $shodanStatus >> "$caseFolder$caseID\spam-report.txt"
} 

if ( $shodanCertIssuer -imatch "Let's Encrypt" ) {
    $shodanStatus = "RISKY CERTIFICATE AUTHORITY DETECTED! Shodan has reported $link's CA as Let's Encrypt. Full details available here: $shodanLink."
    Write-Host $shodanStatus
    $threatScore += 1

    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -command add_note -casenum $caseNumber -note "$shodanStatus" -token $caseAPItoken
    echo $shodanStatus >> "$caseFolder$caseID\spam-report.txt"                       
} elseif ( $shodanTags -imatch "self-signed" ) {
    $shodanStatus = "SELF SIGNED CERTIFICATE DETECTED! Shodan has reported $link's certificates as self-signed. Full details available here: $shodanLink."
    Write-Host $shodanStatus
    $threatScore += 1

    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -command add_note -casenum $caseNumber -note "$shodanStatus" -token $caseAPItoken  
    echo $shodanStatus >> "$caseFolder$caseID\spam-report.txt"     
}

if ( $shodanDetails -eq $true ) {
    $shodanStatus = "====INFO - SHODAN====\r\nInformation on $splitURL`:$shodanIP.\r\nReported location:\r\n Country: $shodanCountry"
    if ( $shodanCity ) { $shodanStatus += "\r\n City: $shodanCity" } 
    if ( $shodanRegion ) { $shodanStatus += "\r\n Region: $shodanRegion" }
    if ( $shodanPostal ) { $shodanStatus += "\r\n Postal: $shodanPostal" }
    if ( $shodanSSL -eq $true ) { $shodanStatus += "\r\nCertificate Authority: $shodanCertIssuer.\r\nExpires on: $shodanCertExpiration" }
    if ( $shodanTags ) { $shodanStatus += "\r\nDetected tags: $shodanTags" }
    $shodanStatus += "\r\nLast scanned on $shodanScanDate."
}
        
& $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -command add_note -casenum $caseNumber -note "$shodanStatus" -token $caseAPItoken

if ( $threatScore -le 0 ) { 
$shodanStatus = "Shodan has determined this link is clean. Full details available here: $shodanLink."
echo $shodanStatus >> "$caseFolder$caseID\spam-report.txt"
Write-Host $shodanStatus
}