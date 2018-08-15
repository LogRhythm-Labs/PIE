#
# Early development of Shodan integration for PIE.  Exploritory to identify potential areas of evidence collection and risk assessment acceleration.
#   
# Goals:
# <in-progress> - Collect additional evidence on link.  Geographic location, IP address, Certificate Authority & expiration.
# <complete>  - Initially groom to find LetsEncrypt Self-Registration certificates.  This may be a point to increase threatScore.
# <incomplete> Explore examination of services running on host.  Example, if identifying tor/tftp/ftp or other file delivery services found in conjuction with HTTP/HTTPS, increase threatScore.
#
# Mask errors
$ErrorActionPreference= 'continue'

$links = "google.com"

# Shodan.io
$shodan = $true
$shodanAPI = "duh deh deh deh deh duh duh duh dah duh"

if ( $shodan -eq $true ) {

    $links | ForEach-Object {
        #$splitLink = ([System.Uri]"$_").Host
        $splitLink = $links
        #Query Shodan DNS.  Required for Shodan Host scan.
        $shodanIPQuery = iwr "https://api.shodan.io/dns/resolve?hostnames=$splitLink&key=$shodanAPI"
        $shodanIPQuery.RawContent | Out-File .\shodanIPQuery.txt
        $shodanIPInfo = Get-Content .\shodanIPQuery.txt | select -Skip 14 | ConvertFrom-Json
        $shodanIP = $shodanIPInfo.$splitLink
        $shodanLink = "https://www.shodan.io/host/$shodanIP"
        #Query Shodan Host scan.
        $shodanHostLookup = iwr "https://api.shodan.io/shodan/host/$shodanIP`?key=$shodanAPI"
        $shodanHostLookup.RawContent | Out-File .\shodanHost.txt
        $shodanHostInfo = (Get-Content .\shodanHost.txt) | select -Skip 14 | ConvertFrom-Json
        $shodanScanDate = $shodanHostInfo.last_update
        $shodanCountry = $shodanHostInfo.country_name
        $shodanCity = $shodanHostInfo.city
        $shodanPorts = $shodanHostInfo.ports
        $shodanTags = $shodanHostInfo.data | Select-Object -ExpandProperty tags -Unique
        #Determine if HTTPS services identified.
        $shodanModules = $shodanHostInfo.data | Select-Object -ExpandProperty _shodan | Select-Object -ExpandProperty module
        #If HTTPS identified populate associated variables.
        if ( $shodanModules -imatch "https" ) {
            $shodanSSL = $true
            $shodanCert1 = $shodanHostInfo.data | Select-Object -ExpandProperty ssl
            $shodanCertIssuer = $shodanCert1.cert.issuer.CN
            $shodanCertExpiration = $shodanCert1.cert.expires
        } else {
            Write-Host "Scanned host does not run any HTTPS services."
            $shodanSSL = $false
            $shodanCert1 = $null
            $shodanCertIssuer = $null
            $shodanCertExpiration = $null
        }
        if ( $shodanCert1.cert.expired -eq $true ) {
            $shodanStatus = "EXPIRED CERTIFICATE! Shodan has reported $splitLink has expired certificates. Last scanned on $shodanScanDate.  Full details available here: $shodanLink."
            $threatScore += 1

            & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -command add_note -casenum $caseNumber -note "$shodanStatus" -token $caseAPItoken
        } 
        if ( $shodanCertIssuer -imatch "Let's Encrypt" ) {
            $shodanStatus = "RISKY CERTIFICATE AUTHORITY DETECTED! Shodan has reported $splitLink's CA as Let's Encrypt. Full details available here: $shodanLink."
            $threatScore += 1

            #& $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -command add_note -casenum $caseNumber -note "$shodanStatus" -token $caseAPItoken                    
        } else {
            $shodanStatus = "Shodan scan identifies no additional risks. Full details available here: $shodanLink."
            Write-Host $shodanStatus
            #& $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -command add_note -casenum $caseNumber -note "$shodanStatus" -token $caseAPItoken
        }
        #Provide additional forensic evidence to case.
        $shodanStatus = "Shodan identifies $splitLink`:$shodanIP.`nReported location:`n Country: $shodanCountry`n City: $shodanCity."
        if ( $shodanSSL -eq $true ) {
            $shodanStatus += "`n`nCertificate Authority: $shodanCertIssuer.`nExpires on: $shodanCertExpiration"
        }
        if ( $shodanTags ) {
            $shodanStatus += "`nDetected tags: $shodanTags"
        }
        $shodanStatus += "`nLast scanned on $shodanScanDate."
        
        Write-Host $shodanStatus
        #& $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -command add_note -casenum $caseNumber -note "$shodanStatus" -token $caseAPItoken

        #echo "============================================================" >> "$caseFolder$caseID\spam-report.txt"
        #echo "" >> "$caseFolder$caseID\spam-report.txt"
        #echo "shodan Status:" >> "$caseFolder$caseID\spam-report.txt"
        #echo "" >> "$caseFolder$caseID\spam-report.txt"
        #echo $shodanStatus >> "$caseFolder$caseID\spam-report.txt"
        #echo "" >> "$caseFolder$caseID\spam-report.txt"
        #Cleanup temporary files.
        Remove-Item -path .\shodan*.txt
    }
}