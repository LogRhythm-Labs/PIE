#====================================#
#       Shodan PIE plugin            #
#         Version 1.5                #
#        Author: Jtekt               #
#====================================#
#
# Licensed under the MIT License. See LICENSE file in the project root for full license information.
#
# Early development of Shodan integration for PIE.  Exploritory to identify potential areas of evidence collection and risk assessment acceleration.
#   
# Goals:
# <complete> - Collect additional evidence on link.  Geographic location, IP address, Certificate Authority & expiration.
# <complete> - Report self-signed certificates.
# <complete> - Initially groom to find LetsEncrypt Self-Registration certificates.  This may be a point to increase threatScore.
# <In Progress> Explore examination of services running on host.  Example, if identifying tor/tftp/ftp or other file delivery services found in conjuction with HTTP/HTTPS, increase threatScore.
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
# Analysis and Reporting
$shodanHostDetails = $true
$shodanSSLDetails = $true
$shodanGameDetails = $true
$threatScore = 0
$IPregex='(?<Address>((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))'
# Optional information.  Will append domain information into LR case.
$shodanDetails = $true

# Query DNS and obtain domain IP address
try {
    $shodanIPQuery = Invoke-RestMethod "https://api.shodan.io/dns/resolve?hostnames=$link&key=$key"
} catch {
    $error =  $_ | Select-String "error"
    Write-Host $error
    Write-Host "Status Code: $($_.Exception.Response.StatusCode.value__)"
    Write-Host "Status Description: $($_.Exception.Response.StatusDescription)"
    $status = "== Shodan Scan Info ==\r\nError on API call\r\nStatus Code: $($_.Exception.Response.StatusCode.value__)\r\nStatus Description: $($_.Exception.Response.StatusDescription)"
}
#$shodanIPQuery = Invoke-RestMethod "https://api.shodan.io/dns/resolve?hostnames=$link&key=$key"
$shodanIPQuery | Where-Object -Property $link -Match $IPregex
$shodanIP = $Matches.Address
$shodanLink = "https://www.shodan.io/host/$shodanIP"

# Query Shodan Host scan
try {
    $shodanHostInfo = Invoke-RestMethod "https://api.shodan.io/shodan/host/$shodanIP`?key=$key"
} catch {
    $error =  $_ | Select-String "error"
    Write-Host "== Shodan Scan Info =="
    Write-Host $error
    Write-Host "Status Code: $($_.Exception.Response.StatusCode.value__)"
    Write-Host "Status Description: $($_.Exception.Response.StatusDescription)"
    $status = "== Shodan Scan Info ==\r\nError on API call\r\nStatus Code: $($_.Exception.Response.StatusCode.value__)\r\nStatus Description: $($_.Exception.Response.StatusDescription)"
}

if ( $shodanHostDetails -eq $true ) {
    $status = "====INFO - SHODAN====\r\nInformation on $link`:$shodanIP\r\nReported location:\r\n Country: $($shodanHostInfo.country_name)"
    if ( $($shodanHostInfo.city) ) { $status += "\r\n City: $($shodanHostInfo.city)" } 
    if ( $($shodanHostInfo.region_code) ) { $status += "\r\n Region: $($shodanHostInfo.region_code)" }
    if ( $($shodanHostInfo.postal_code) ) { $status += "\r\n Postal: $($shodanHostInfo.postal_code)" }
    if ( $($shodanHostInfo.tags) ) { $status += "\r\n Detected tags: $($shodanHostInfo.tags)" }
    if ( $($shodanHostInfo.org) ) { $status += "\r\n Organization: $($shodanHostInfo.org)" }
    if ( $($shodanHostInfo.org) -ne $($shodanHostInfo.isp) ) {
        if ( $($shodanHostInfo.isp) ) { $status += "\r\n Internet Service Provider: $($shodanHostInfo.isp)" }
    }
}

#Break out and report on Shodan data
for($i=0; $i -le ($shodanHostInfo.data.Length-1); $i++){
    $status += "\r\n\r\n*** Service $($shodanHostInfo.data[$i]._shodan.module) ***"
    $status += "\r\nService Summary: $shodanIP`:$($shodanHostInfo.data[$i].port) $($shodanHostInfo.data[$i].transport.ToUpper())"
    if ( $($shodanHostInfo.data[$i].tags) ) { $status += "\r\nReported Tags: $($shodanHostInfo.data[$i].tags)" }
    if ( $($shodanHostInfo.data[$i].product) ) { $status += "\r\nDetected Product: $($shodanHostInfo.data[$i].product)" }
    if ( $($shodanHostInfo.data[$i].http.server) ) { $status += "\r\nHTTP Server: $($shodanHostInfo.data[$i].http.server)" }
    $error = $($shodanHostInfo.data[$i].data) | Select-String -Pattern "ssl error"
    if ( $error ){
        $status += "\r\n$($shodanHostInfo.data[$i].data)"
    }
    #Minecraft
    if ( $shodanGameDetails -eq $true) {
        if ( $shodanHostInfo.data[$i].product -eq "Minecraft" ) {
            $status += "\r\nServer Version: $($shodanHostInfo.data[$i].minecraft.version.name)"
            $status += "\r\nServer Description: $($shodanHostInfo.data[$i].minecraft.description)"
            $status += "\r\nMax Players: $($shodanHostInfo.data[$i].minecraft.players.max)"
            $status += "\r\nCurrent Players: $($shodanHostInfo.data[$i].minecraft.players.online)"
        }
    }
    #SSL
    if ( $shodanHostInfo.data[$i].ssl ){
        $shodanCert1 = $shodanHostInfo.data[$i] | Select-Object -ExpandProperty ssl
        if ( $shodanSSLDetails -eq $true) {
            $status += "\r\n\r\n-- SSL Certificate Observed --"
            $status += "\r\nCertificate Subject: $($shodanCert1.cert.subject)"
            $status += "\r\nCertificate SHA256: $($shodanCert1.cert.fingerprint.sha256)"
            $status += "\r\nCertificate Issuer: $($shodanCert1.cert.issuer)"
            $status += "\r\nCertificate Issue date: $($shodanCert1.cert.issued)"
            $status += "\r\nCertificate Expiration date: $($shodanCert1.cert.expires)"
            $status += "\r\nSupported Ciphers: $($shodanCert1.cipher)\r\n"
        }
        if ( $($shodanCert1.cert.expired) -eq $true ) {
            $status += "\r\nALERT: Expired Certificate Detected!"
            $threatScore += 1
        }
        if ( $($shodanCert1.cert.issuer) -imatch "Let's Encrypt" ) {
            $status += "\r\nALERT: Let's Encrypt Certificate Authority Detected!"
            $threatScore += 1        
        } elseif ( $($shodanHostInfo.data[$i].tags) -imatch "self-signed" ) {
            $status += "\r\nALERT: Self Signed Certificate Detected!"
            $threatScore += 1
        }
    }
    #FTP
    if ( $shodanHostInfo.data[$i]._shodan.module -eq "ftp" ) {
        $status += "\r\nAnonymous Login: $($shodanHostInfo.data[$i].ftp.anonymous)"
        $threatScore += 1
    }   
}
$status += "\r\n\r\n**** End Service Summary ****"
$status += "\r\n\r\nLast scanned on $($shodanHostInfo.last_update).  Full details available here: $shodanLink."
& $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$status" -token $caseAPItoken
$status += "\r\n**** End Shodan Entry for $link ****\r\n\r\n"
echo $status.Replace("\r\n","`r`n") >> "$caseFolder$caseID\spam-report.txt"