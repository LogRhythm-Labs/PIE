#====================================#
#       Wildfire PIE plugin          #
#         Version 0.4                #
#        Author: Jtekt               #
#====================================#
#
# Licensed under the MIT License. See LICENSE file in the project root for full license information.
#
# Early development of Wildfire integration for PIE. 
#   
# Goals:
# <Complete> - Send MD5 or SHA256 hash to Wildfire API for results.  If results show malicious, return details.
# <Complete> - PIE reporting.
#
# 
# <Not Started> - Send bulk MD5 or SHA256 - Will reduce number of API calls to support large installations.
# <Not Started> - URL inspection.
# 
#

# .\Wildfire.ps1 -key $wildfireAPI -fileHash $fileHash -fileName $fileName -caseID $caseID -caseFolder $caseFolder -pieFolder $pieFolder -logRhythmHost $logRhythmHost -caseAPItoken $caseAPItoken

[CmdLetBinding()]
param( 
    [string]$key,
    [string]$fileHash,
    [string]$fileName,
    [string]$caseID,
    [string]$caseFolder,
    [string]$pieFolder,
    [string]$LogRhythmHost,
    [string]$caseAPItoken
)
#Temp Variables
$key = Get-Content D:\nCloud\Projects\git\wildfire\key.txt
$tmpFolder = ".\"
$fileName = "myworkbook.xls"
$fileHash = "dca86121cc7427e375fd24fe5871d727"


# Mask errors
$ErrorActionPreference= 'continue'


# Global Parameters
$IPregex='(?<Address>((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))'
#Future use, validators
$MD5regex='(?<Hash>([a-f0-9]{32}))'
$SHA256regex='(?<Hash>([A-Fa-f0-9]{64}))'

#Hash validation


if ( $fileHash ) {
    #Get verdict - single lookup - Simple lookup
    [xml]$wfQuery = Invoke-WebRequest -uri "https://wildfire.paloaltonetworks.com/publicapi/get/verdict" -Method Post -Body "apikey=$key;hash=$fileHash;format=xml"
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
            Write-Host "Submitted hash value is currently pending evaluation."
            echo "Palo Alto Wildfire Results" >> "$caseFolder$caseID\spam-report.txt"
            echo "Submitted file: $fileName" >> "$caseFolder$caseID\spam-report.txt"
            echo "Submitted hash: $fileHash" >> "$caseFolder$caseID\spam-report.txt"
            echo "Wildfire Verdict: Status Pending" >> "$caseFolder$caseID\spam-report.txt"
        }
        0{
            #0 FIle identified as bening
            Write-Host "Submitted hash value is confirmed bening."
            echo "Palo Alto Wildfire Results" >> "$caseFolder$caseID\spam-report.txt"
            echo "Submitted file: $fileName" >> "$caseFolder$caseID\spam-report.txt"
            echo "Submitted hash: $fileHash" >> "$caseFolder$caseID\spam-report.txt"
            echo "Wildfire Verdict: File Bening" >> "$caseFolder$caseID\spam-report.txt"
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
        [xml]$wfReport = Invoke-WebRequest -uri "https://wildfire.paloaltonetworks.com/publicapi/get/report" -Method Post -Body "apikey=$key;hash=$fileHash;format=xml"
        $wfMalware = $wfReport.wildfire.file_info.malware
        $wfFiletype = $wfReport.wildfire.file_info.filetype
        $wfFileMd5 = $wfReport.wildfire.file_info.md5
        $wfFileSha256 = $wfReport.wildfire.file_info.sha256
        $wfFileSize = $wfReport.wildfire.file_info.size
        $wfStatus = "MALICIOUS FILE DETECTED! Wildfire has reported $fileName as Malware.\r\nWildfire Information:\r\n File Type: $wfFiletype\r\n File MD5: $wfFileMd5\r\n File SHA256: $wfFileSha256\r\n File Size: $wfFileSize"
        Write-Host $wfStatus
        $threatScore += 1

        #& $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$wfStatus" -token $caseAPItoken
        #Write-Host "*************************************"
        echo "Palo Alto Wildfire Results" >> "$caseFolder$caseID\spam-report.txt"
        echo "Submitted file: $fileName" >> "$caseFolder$caseID\spam-report.txt"
        echo "Submitted hash: $fileHash" >> "$caseFolder$caseID\spam-report.txt"
        echo "Wildfire Malware Verdict: $wfMalware" >> "$caseFolder$caseID\spam-report.txt"
        echo "Wildfire returned hashes: MD5 $wfFileMd5 SHA256 $wfFileSha256" >> "$caseFolder$caseID\spam-report.txt"
        echo "Wildfire Reported File Size: $wfFileSize" >> "$caseFolder$caseID\spam-report.txt"
        echo "Wildfire Reported File Type: $wfFiletype" >> "$caseFolder$caseID\spam-report.txt"

    }

}