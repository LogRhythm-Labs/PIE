#====================================#
#       Wildfire PIE plugin          #
#         Version 0.2                #
#        Author: Jtekt               #
#====================================#
#
# Licensed under the MIT License. See LICENSE file in the project root for full license information.
#
# Early development of Wildfire integration for PIE. 
#   
# Goals:
# <In Progress> - Send MD5 or SHA256 hash to Wildfire API for results.  If results show malicious, return details.
# <In Progress> - Send bulk MD5 or SHA256 - Will reduce number of API calls to support large installations.
# <Not Started> - URL inspection.
# <Not Started> - PIE ingestion.
#

# .\Wildfire.ps1 -key $wildfireAPI -checkLink $link -checkFile $file|$hash -caseID $caseID -caseFolder $caseFolder -pieFolder $pieFolder -logRhythmHost $logRhythmHost -caseAPItoken $caseAPItoken

[CmdLetBinding()]
param( 
    [string]$key,
    [string]$checkLink,
    [string]$checkFile,
    [string]$caseID,
    [string]$caseFolder,
    [string]$pieFolder,
    [string]$LogRhythmHost,
    [string]$caseAPItoken
)
#Temp Variables
$key = ''
#$hash = "dca86121cc7427e375fd24fe5871d727"
#$checkFile = "C:\hashlist.txt"
$checkLink = "http://paloaltonetworks.com"
$tmpFolder = ".\"
#if ( !$hash -eq $true ) {
#    $temp_hash = Get-FileHash $file -Algorithm SHA256
#    $hash = $temp_hash.hash
#}


# Mask errors
$ErrorActionPreference= 'continue'


# Global Parameters
$IPregex='(?<Address>((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))'

if ( $checkFile ) {
    #Get verdict - single lookup - Simple lookup
    [xml]$wfQuery = Invoke-WebRequest -uri "https://wildfire.paloaltonetworks.com/publicapi/get/verdict" -Method Post -Body "apikey=$key;hash=$hash;format=xml"
    $wfVerdict = $wfQuery.wildfire.'get-verdict-info'.verdict
    Write-Host $wfVerdict
    switch ( $wfVerdict )
    {
        -103{
            #-103 Invalid hash code submitted
            Write-Host "Invalid hash value submitted to Palo Alto Wildfire."
        }
        -102{
            #-102 Record not in database
            Write-Host "Hash value not found within Palo Alto Wildfire database." 
        }
        -101{
            #-101 Error occured with Palo Alto Wildfire API
            Write-Host "An error occured within the Wildfire API." 
        }
        -100{
            #-100 Hash is currently pending
            WRite-Host "Submitted hash value is currently pending evaluation."
        }
        0{
            #0 FIle identified as bening
            Write-Host "Submitted hash value is confirmed bening."
        }
        1{
            #1 File identified as malware
            Write-Host "Submitted hash value is confirmed as malware."
        }
        2{
            #2 File identified as grayware
            Write-Host "Submitted hash value is confirmed as grayware."
        }
        default{
            #Unknown error occured
            Write-Host "An unknown error has occured within Wildfire.ps1."
        }
    }
    if ( $wfVerdict -eq "1" -or $wfVerdict -eq "2" ) {
        [xml]$wfQuery = Invoke-WebRequest -uri "https://wildfire.paloaltonetworks.com/publicapi/get/report" -Method Post -Body "apikey=$key;hash=$hash;format=xml"
        #$wfQuery.RawContent | Out-File $tmpFolder\wfAnalysis.txt
        #[xml]$wfResults = Get-Content $tmpFolder\wfAnalysis.txt | select -Skip 7
        #### Are there results?!####
        ## If yes, proceed to evaluate
        ## If no, upload file
        #Write-Host "====================================="
        $wfMalware = $wfQuery.wildfire.file_info.malware
        $wfFiletype = $wfQuery.wildfire.file_info.filetype
        $wfFileMd5 = $wfQuery.wildfire.file_info.md5
        $wfFileSha256 = $wfQuery.wildfire.file_info.sha256
        $wfFileSize = $wfQuery.wildfire.file_info.size
        Write-Host "Wildfire record for $hash.  Is it malware: $wfMalware File Type: $wfFiletype File Size: $wfFileSize MD5: $wfFileMd5  SHA256: $wfFileSha256"
        #Write-Host "*************************************"
    }

}

#Not working
<#
if ( $checkLink ) {
    Write-Host $checkLink
    $payload = "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; name=`"apikey`"\r\n\r\$key\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; name=`"link`"\r\n\r\$checkLink\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; name=\`format\`\r\n\r\nxml\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW--"
    Write-Host $payload
    $wfQuery2 = Invoke-WebRequest -uri "https://wildfire.paloaltonetworks.com/publicapi/submit/link" -Method Post -Body $payload

}
#>



#Old code

<#
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

    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$shodanStatus" -token $caseAPItoken
    echo $shodanStatus >> "$caseFolder$caseID\spam-report.txt"
} 

if ( $shodanCertIssuer -imatch "Let's Encrypt" ) {
    $shodanStatus = "RISKY CERTIFICATE AUTHORITY DETECTED! Shodan has reported $link CA as Let's Encrypt. Full details available here: $shodanLink."
    Write-Host $shodanStatus
    $threatScore += 1

    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$shodanStatus" -token $caseAPItoken
    echo $shodanStatus >> "$caseFolder$caseID\spam-report.txt"                       
} elseif ( $shodanTags -imatch "self-signed" ) {
    $shodanStatus = "SELF SIGNED CERTIFICATE DETECTED! Shodan has reported $link certificates as self-signed. Full details available here: $shodanLink."
    Write-Host $shodanStatus
    $threatScore += 1

    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$shodanStatus" -token $caseAPItoken  
    echo $shodanStatus >> "$caseFolder$caseID\spam-report.txt"     
}

if ( $shodanDetails -eq $true ) {
    $shodanStatus = "====INFO - SHODAN====\r\nInformation on $link`:$shodanIP.\r\nReported location:\r\n Country: $shodanCountry"
    if ( $shodanCity ) { $shodanStatus += "\r\n City: $shodanCity" } 
    if ( $shodanRegion ) { $shodanStatus += "\r\n Region: $shodanRegion" }
    if ( $shodanPostal ) { $shodanStatus += "\r\n Postal: $shodanPostal" }
    if ( $shodanSSL -eq $true ) { $shodanStatus += "\r\nCertificate Authority: $shodanCertIssuer.\r\nExpires on: $shodanCertExpiration" }
    if ( $shodanTags ) { $shodanStatus += "\r\nDetected tags: $shodanTags" }
    $shodanStatus += "\r\nLast scanned on $shodanScanDate."

    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$shodanStatus" -token $caseAPItoken

}
        
if ( $threatScore -le 0 ) { 
    $shodanStatus = "Shodan has determined $link is clean. Full details available here: $shodanLink."
    echo $shodanStatus >> "$caseFolder$caseID\spam-report.txt"
    Write-Host $shodanStatus
    & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$shodanStatus" -token $caseAPItoken
}
#>