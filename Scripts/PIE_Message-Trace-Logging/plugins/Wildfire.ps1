#====================================#
#       Wildfire PIE plugin          #
#         Version 0.8                #
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


# Mask errors
$ErrorActionPreference= 'continue'


# Global Parameters
#Future use, validators
$IPregex='(?<Address>((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))'
$MD5regex='(?<Hash>([a-f0-9]{32}))'
$SHA256regex='(?<Hash>([A-Fa-f0-9]{64}))'


if ( $fileHash ) {
    #Get verdict - single lookup - Simple lookup
    [xml]$wfQuery = Invoke-WebRequest -uri "https://wildfire.paloaltonetworks.com/publicapi/get/verdict" -Method Post -Body "apikey=$key;hash=$fileHash;format=xml"
    $wfVerdict = $wfQuery.wildfire.'get-verdict-info'.verdict
    switch ( $wfVerdict )
    {
        -103{
            #-103 Invalid hash code submitted
            Write-Verbose "Invalid hash value submitted to Palo Alto Wildfire."
            
            $wfStatus = "====ERROR - WILDFIRE====\r\nInvalid Hash format supplied.\r\n\r\nWildfire Information:\r\n File Name: $fileName\r\n File SHA256: $fileHash\r\n\r\nPlease check the hash format and manually submit at: https://wildfire.paloaltonetworks.com/."
            
            & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$wfStatus" -token $caseAPItoken
            echo "Palo Alto Wildfire Results" >> "$caseFolder$caseID\spam-report.txt"
            echo "Submitted file: $fileName" >> "$caseFolder$caseID\spam-report.txt"
            echo "Submitted hash: $fileHash" >> "$caseFolder$caseID\spam-report.txt"
            echo "Wildfire Verdict: Invalid Hash Format Reported" >> "$caseFolder$caseID\spam-report.txt"
        }
        -102{
            #-102 Record not in database
            Write-Verbose "Hash value not found within Palo Alto Wildfire database." 
            
            $wfStatus = "====INFO - WILDFIRE====\r\nWildfire has no data on submitted hash.\r\n\r\nWildfire Information:\r\n File Name: $fileName\r\n File SHA256: $fileHash\r\n\r\nSubmit file for Wildfire analyis at: https://wildfire.paloaltonetworks.com/."
            
            & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$wfStatus" -token $caseAPItoken
            echo "Palo Alto Wildfire Results" >> "$caseFolder$caseID\spam-report.txt"
            echo "Submitted file: $fileName" >> "$caseFolder$caseID\spam-report.txt"
            echo "Submitted hash: $fileHash" >> "$caseFolder$caseID\spam-report.txt"
            echo "Wildfire Verdict: Hash not found within Wildfire database" >> "$caseFolder$caseID\spam-report.txt"
        }
        -101{
            #-101 Error occurred with Palo Alto Wildfire API
            Write-Verbose "An error occurred within the Wildfire API." 

            $wfStatus = "====ERROR - WILDFIRE====\r\nWildfire has encountered an API error.\r\n\r\nWildfire Information:\r\n File Name: $fileName\r\n File SHA256: $fileHash\r\n\r\nRe-check file status at later time."
            
            & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$wfStatus" -token $caseAPItoken

            echo "Palo Alto Wildfire Results" >> "$caseFolder$caseID\spam-report.txt"
            echo "Submitted file: $fileName" >> "$caseFolder$caseID\spam-report.txt"
            echo "Submitted hash: $fileHash" >> "$caseFolder$caseID\spam-report.txt"
            echo "Wildfire Verdict: An internal API error has been returned" >> "$caseFolder$caseID\spam-report.txt"
        }
        -100{
            #-100 Hash is currently pending
            Write-Verbose "Submitted hash value is currently pending evaluation."

            $wfStatus = "====INFO - WILDFIRE====\r\nWildfire has reported $fileName as pending.\r\n\r\nWildfire Information:\r\n File Name: $fileName\r\n File SHA256: $fileHash\r\n\r\nRe-check file status at later time."
            
            & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$wfStatus" -token $caseAPItoken

            echo "Palo Alto Wildfire Results" >> "$caseFolder$caseID\spam-report.txt"
            echo "Submitted file: $fileName" >> "$caseFolder$caseID\spam-report.txt"
            echo "Submitted hash: $fileHash" >> "$caseFolder$caseID\spam-report.txt"
            echo "Wildfire Verdict: Status Pending" >> "$caseFolder$caseID\spam-report.txt"
        }
        0{
            #0 FIle identified as benign
            Write-Verbose "Submitted hash value is confirmed benign."
            
            $wfStatus = "====INFO - WILDFIRE====\r\nWildfire has reported $fileName as benign.\r\n\r\nWildfire Information:\r\n File Name: $fileName\r\n File SHA256: $fileHash"
            
            & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$wfStatus" -token $caseAPItoken

            echo "Palo Alto Wildfire Results" >> "$caseFolder$caseID\spam-report.txt"
            echo "Submitted file: $fileName" >> "$caseFolder$caseID\spam-report.txt"
            echo "Submitted hash: $fileHash" >> "$caseFolder$caseID\spam-report.txt"
            echo "Wildfire Verdict: File Benign" >> "$caseFolder$caseID\spam-report.txt"
        }
        1{
            #1 File identified as malware
            Write-Verbose "Submitted hash value is confirmed as malware."
        }
        2{
            #2 File identified as grayware
            Write-Verbose "Submitted hash value is confirmed as grayware."
        }
        default{
            #Unknown error occurred
            Write-Verbose "An unknown error has occurred within Wildfire.ps1."
            
            $wfStatus = "====ERROR - WILDFIRE SCRIPT====\r\nAn unknown error has occurred.\r\n\r\nWildfire Information:\r\n File Name: $fileName\r\n File SHA256: $fileHash\r\n\r\nPlease check the hash format and manually submit at: https://wildfire.paloaltonetworks.com/."
            
            & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$wfStatus" -token $caseAPItoken

            echo "Palo Alto Wildfire Results" >> "$caseFolder$caseID\spam-report.txt"
            echo "Submitted file: $fileName" >> "$caseFolder$caseID\spam-report.txt"
            echo "Submitted hash: $fileHash" >> "$caseFolder$caseID\spam-report.txt"
            echo "Wildfire Verdict: An unspecified error has occurred" >> "$caseFolder$caseID\spam-report.txt"
        }
    }
    if ( $wfVerdict -eq "1" -or $wfVerdict -eq "2" ) {
        [xml]$wfReport = Invoke-WebRequest -uri "https://wildfire.paloaltonetworks.com/publicapi/get/report" -Method Post -Body "apikey=$key;hash=$fileHash;format=xml"
        $wfMalware = $wfReport.wildfire.file_info.malware
        $wfFiletype = $wfReport.wildfire.file_info.filetype
        $wfFileMd5 = $wfReport.wildfire.file_info.md5
        $wfFileSha256 = $wfReport.wildfire.file_info.sha256
        $wfFileSize = $wfReport.wildfire.file_info.size
        $wfStatus = "====ALERT - WILDFIRE====\r\nMALICIOUS FILE DETECTED! Wildfire has reported $fileName as Malware.\r\n\r\nWildfire Information:\r\n File Type: $wfFiletype\r\n File MD5: $wfFileMd5\r\n File SHA256: $wfFileSha256\r\n File Size: $wfFileSize"
        Write-Verbose $wfStatus
        $threatScore += 1

        & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -casenum $caseNumber -updateCase "$wfStatus" -token $caseAPItoken

        echo "Palo Alto Wildfire Results" >> "$caseFolder$caseID\spam-report.txt"
        echo "Submitted file: $fileName" >> "$caseFolder$caseID\spam-report.txt"
        echo "Submitted hash: $fileHash" >> "$caseFolder$caseID\spam-report.txt"
        echo "Wildfire Malware Verdict: $wfMalware" >> "$caseFolder$caseID\spam-report.txt"
        echo "Wildfire returned hashes: MD5 $wfFileMd5 SHA256 $wfFileSha256" >> "$caseFolder$caseID\spam-report.txt"
        echo "Wildfire Reported File Size: $wfFileSize" >> "$caseFolder$caseID\spam-report.txt"
        echo "Wildfire Reported File Type: $wfFiletype" >> "$caseFolder$caseID\spam-report.txt"

    }

}