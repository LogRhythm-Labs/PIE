#requires -version 3.0

  #=======================================#
  # LogRhythm Security Operations         #
  # Cisco AMP ThreatGRID - PIE PowerShell #
  # greg . foss [at] logrhythm . com      #
  # bruce . deakyne [at] logrhythm . com  #
  # v0.7  --  May 2017                    #
  #=======================================#

# For more information on Cisco AMP ThreatGRID, please see their website:
#     http://www.cisco.com/c/en/us/solutions/enterprise-networks/amp-threat-grid/index.html

# Copyright 2017 LogRhythm Inc.   
# Licensed under the MIT License. See LICENSE file in the project root for full license information.

[CmdLetBinding()]
param( 
    [string]$key,
    [string]$hash,
    [string]$file,
    [string]$url,
    [string]$domainName,
    [string]$ipAddress,
    [string]$caseNumber,
    [string]$caseFolder,
    [string]$LogRhythmHost,
    [string]$caseAPItoken
)

function ThreatGRID {

<#
.NAME
    Cisco AMP Threat Grid SmartResponse

.SYNOPSIS
    PowerShell Cisco AMP Threat Grid API Integration and Automated Alerting

.DESCRIPTION
    This script is meant to integrate with security infrastructure, such as a SIEM in order to automate the analysis of new processes and/or files

.NOTES
    This tool is designed to be executed from a LogRhythm SmartResponse(TM) on remote hosts via the LogRhythm agent, remotely using the LogRhythm SIEM, or locally/remotely as a standalone PowerShell script.
    The safest way to run this script is locally, however remote execution is possible. Realize this will open the system up to additional risk...

.EXAMPLE
Check a file against Cisco AMP Threat Grid
    PS C:\> .\ThreatGRID.ps1 -file "C:\Users\taco\Desktop\eicar.txt"

.EXAMPLE
Check a domain against Cisco AMP Threat Grid
    PS C:\> .\ThreatGRID.ps1 -domainName logrhythm.com

.EXAMPLE
Check a domain against Cisco AMP Threat Grid
    PS C:\> .\ThreatGRID.ps1 -ipAddress 192.168.0.123

.EXAMPLE
Check an MD5 / SHA1 / SHA256 hash against Cisco AMP Threat Grid
    PS C:\> .\ThreatGRID.ps1 -hash 1df22320a01a11630f955b74d3a232a2b5352104c650b1738fe152360e278613 #cryptowall sample

.OUTPUTS
    -Host IP Address
    -Host Name
    -Scan Date
    -Process Name
    -Process ID
    -Associated File
    -SHA256 Hash
    -SHA1 Hash
    -MD5 Hash
    -Cisco AMP Threat Grid Data and IOC's
#>

# Mask errors
#$ErrorActionPreference= 'silentlycontinue'

#=======================================================================================
# HASHING
#=======================================================================================

function Get-Hash(
    [System.IO.FileInfo] $file = $(Throw 'Usage: Get-Hash [System.IO.FileInfo]'), 
    [String] $hashType = 'sha256')
{
  $stream = $null;  
  [string] $result = $null;
  $hashAlgorithm = [System.Security.Cryptography.HashAlgorithm]::Create($hashType )
  $stream = $file.OpenRead();
  $hashByteArray = $hashAlgorithm.ComputeHash($stream);
  $stream.Close();

  trap
  {
    if ($stream -ne $null) { $stream.Close(); }
    break;
  }

  # Convert the hash to Hex
  $hashByteArray | foreach { $result += $_.ToString("X2") }
  return $result
}

function Get-Bytes([String] $str) {
    $bytes = New-Object Byte[] ($str.Length * 2)
    #[System.Buffer]::BlockCopy($str.ToCharArray(), 0, $bytes, 0, $bytes.Length)
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($str)
    return $bytes
}

#=======================================================================================
# DISCOVERY
#=======================================================================================

if (-Not ( $file )) {
    if (-Not ( $domainName )) {
        if (-Not ( $ipAddress )) {
            if (-Not ( $hash )) {
                if (-Not ( $url )) {
                    Write-Host ""
                    write-Host "Specify a process (-processName / -processID), file (-file), URL, IP Address or Domain (-url / -ipAddress / -domainName), Hash (-hash) and try again..."
                    Exit 1
                }
            }
        }
    }
}

if ( $file ) {
    $hizzash = Get-Hash -file $file
    $leSample = "File => $file"
}
if ( $hash ) {
    $hizzash = $hash
    $leSample = "Hash => $hizzash"
}

#=======================================================================================
# API ACTIONS
#=======================================================================================

# Process / File / Hash
if ( $hizzash ) {
    Invoke-RestMethod -Method GET -Uri "https://panacea.threatgrid.com/api/v2/search/submissions?term=sample&q=$hizzash&api_key=$key" -OutVariable fileResults
    $total = $fileResults.data.total
    $results = $fileResults.data.items | Format-Custom
}

# IP Address
if ( $url ) {
    Invoke-RestMethod -Method GET -Uri "https://panacea.threatgrid.com/api/v2/search/submissions?q=$url&api_key=$key" -OutVariable URLResults
    $total = $URLResults.data.total
    $results = $URLResults.data.items | Format-Custom
    $leSample = "URL => $URLResults"
}

# Domain
if ( $domainName) {
    Invoke-RestMethod -Method GET -Uri "https://panacea.threatgrid.com/api/v2/search/submissions?term=domain&q=$domainName&api_key=$key" -OutVariable domainResults
    $total = $domainResults.data.total
    $results = $domainResults.data.items | Format-Custom
    $leSample = "Domain Name => $domainName"
}

# IP Address
if ( $ipAddress ) {
    Invoke-RestMethod -Method GET -Uri "https://panacea.threatgrid.com/api/v2/search/submissions?q=$ipAddress&api_key=$key" -OutVariable IPResults
    $total = $IPResults.data.total
    $results = $IPResults.data.items | Format-Custom
    $leSample = "IP Address => $ipAddress"
}

#=======================================================================================
# REPORTING
#=======================================================================================

if ( $total -gt 50 ) {
    
    $malwareName = $results | findstr detected | sort -Unique
    if ( $malwareName ) { 
        $malwareName = $malwareName.Split() | where {$_} |findstr -v "= name"
    } else {
        $malwareName = "sample not yet tagged"
    }
    
    $threatScore = $results | findstr "threat_score"
    $threatScore = $threatScore.split()| where {$_} | sort -Unique | findstr /r "^[0-9]"
    if ( $threatScore -lt 50 ) {
        $risk = "Potentially Unwanted Software Detected"
    } else {
        $risk = "Malicious Sample Detected!"
    }

    $submitted = $results | findstr "submitted_at"
    $submitted = $submitted.split()| where {$_} | sort -Unique | findstr -v "submitted_at ="
    $md5 = $results | findstr "md5"
    $md5 = $md5.split()| where {$_} | sort -Unique | findstr -v "md5 ="
    $sha1 = $results | findstr "sha1"
    $sha1 = $sha1.split()| where {$_} | sort -Unique | findstr -v "sha1 ="
    $sha256 = $results | findstr "sha256"
    $sha256 = $sha256.split()| where {$_} | sort -Unique | findstr -v "sha256 ="
    $fileName = $results | findstr "filename"
    $fileName = $fileName.split()| where {$_} | sort -Unique | findstr /r "\.[a-z0-9+]" | findstr -v "filename"
    $fileType = $results | findstr "type"
    $fileType = $fileType.split()| where {$_} | sort -Unique | findstr -v "type ="
    $fileDetails = $results | findstr "magic"
    $fileDetails = $fileDetails.Substring(28)| sort -Unique
    if ( $processID ) { $fileName = $file }
    if ( $processName ) { $fileName = $file }
    
    if ( $total -gt 1 ) {
        $malwareNames = $malwareName | foreach {$_ + ","}
        $threatScores = $threatScore | foreach {$_ + ","}
        $submissions = $submitted | foreach {$_ + ","}
        $md5Sums = $md5 | foreach {$_ + ","}
        $sha1Sums = $sha1 | foreach {$_ + ","}
        $sha256Sums = $sha256 | foreach {$_ + ","}
        $fileNames = $fileName | foreach {$_ + ","}
        $fileTypes = $fileType | foreach {$_ + ","}
        $fileMagicDetails = $fileDetails | foreach {$_ + ","}
    }

} else {

    # FILE
    if ( $file ) {
	    # Read the file contents in as a byte array
		$fileName = Split-Path $file -leaf
        $FilePath = Split-Path $file -Parent
        $bytes = Get-Content $file -Encoding Byte
		$enc = [System.Text.Encoding]::GetEncoding("iso-8859-1")
		$FileContent = $enc.GetString($bytes)

		# Body of the request
		# Each parameter is in a new multipart boundary section
		# We don't do much with os/os version/source yet
		$Body = (
			"------------MULTIPARTBOUNDARY_`$",
			'Content-Disposition: form-data; name="api_key"',
			"",
			$key,
			"------------MULTIPARTBOUNDARY_`$",
			'Content-Disposition: form-data; name="filename"',
			"",
			$fileName,
			"------------MULTIPARTBOUNDARY_`$",
			'Content-Disposition: form-data; name="tags"',
			"",
			"LR-SmartResponse",
			"------------MULTIPARTBOUNDARY_`$",
			'Content-Disposition: form-data; name="os"',
			"",
			"",
			"------------MULTIPARTBOUNDARY_`$",
			'Content-Disposition: form-data; name="osver"',
			"",
			"",
			"------------MULTIPARTBOUNDARY_`$",
			'Content-Disposition: form-data; name="source"',
			"",
			"",

			# This is the file itself
			"------------MULTIPARTBOUNDARY_`$",
			("Content-Disposition: form-data; name=`"sample`"; filename=`"${fileName}`""),
			("Content-Type: `"${fileType}`""),
			"",
			$fileContent,
			"------------MULTIPARTBOUNDARY_`$--",
			""
		) -join "`r`n"

		# Tell TG what the content-type is and what the boundary looks like
		$ContentType = 'multipart/form-data; boundary=----------MULTIPARTBOUNDARY_$'

		$Uri = "https://panacea.threatgrid.com/api/v2/samples"
		try {
			
            # Update the case
            $caseUpdate = "Uploading the sample ($fileName) to Cisco AMP Threat Grid. Please allow up to 10 minutes for the analysis to complete..."
            & .\Case-API.ps1 -lrhost $LogRhythmHost -command add_note -casenum $caseNumber -note "$caseUpdate" -token $caseAPItoken

            # Call ThreatGRID
			$Response = Invoke-RestMethod -Uri $Uri -method POST -Body $Body -ContentType $ContentType 
			return $Response.data

            $Response.data
            $sampleId = $Response.data.id
            
            echo "" >> $caseFolder\ThreatGRID-results.txt
            echo "Sample Submitted to Cisco AMP Threat Grid:" 
            echo "============================================================" >> $caseFolder\ThreatGRID-results.txt
            $Response.data >> $caseFolder\ThreatGRID-results.txt
            echo "============================================================" >> $caseFolder\ThreatGRID-results.txt
            echo "" >> $caseFolder\ThreatGRID-results.txt

            # Launch status script and allow 10 minutes for analysis to complete
            & .\ThreatGRID-PIE_Status.ps1 -ApiKey $key -SampleId $sampleId -caseNumber $caseNumber -caseFolder "$caseFolder" -caseAPItoken $caseAPItoken -LogRhythmHost $LogRhythmHost
		}
		catch {
			# Oh no, it failed!
			write-host "Failed to upload" $FileName "to Cisco AMP ThreatGRID"
			return $null

            $caseUpdate = "Failed to upload $FileName to Cisco AMP ThreatGRID"
            & .\Case-API.ps1 -lrhost $LogRhythmHost -command add_note -casenum $caseNumber -note "$caseUpdate" -token $caseAPItoken
		}
	} else {
        write-host "This sample is not currently present in Cisco AMP Threat Grid and PIE was unable to submit the sample. Please visit the Cisco AMP ThreatGRID website analyze the file directly."
        $caseUpdate = "This sample is not currently present in Cisco AMP Threat Grid and PIE was unable to submit the sample. Please visit the Cisco AMP ThreatGRID website analyze the file directly."
        & .\Case-API.ps1 -lrhost $LogRhythmHost -command add_note -casenum $caseNumber -note "$caseUpdate" -token $caseAPItoken
    }
}


#=======================================================================================
# HTML REPORT GENERATION
#=======================================================================================

if ( $total.count -eq 0 ) {
    
    $caseUpdate = "This sample is not currently present in Cisco AMP Threat Grid and PIE was unable to submit the sample. Please visit the Cisco AMP ThreatGRID website analyze the file directly."
    & .\Case-API.ps1 -lrhost $LogRhythmHost -command add_note -casenum $caseNumber -note "$caseUpdate" -token $caseAPItoken

} else {

    Write-Host ""
    if ( $total.count -gt 1 ) {
        $messageTitle = "Malicious Sample Detected!"
        $message = @"
Cisco AMP Threat Grid has Detected Multiple Indicators

Malware Name :  $malwareName
Sample       :  $leSample
Threat Scores:
$threatScores

MD5 Hashes:
$md5Sums

SHA1 Hashes:
$sha1Sums

SHA256 Hashes:
$sha256Sums

File Names:
$fileNames

File Types:
$fileTypes

File Magic:
$fileMagicDetails

Submission Dates:
$submissions

"@
        $message
        echo "" >> $caseFolder\ThreatGRID-results.txt
        echo "Cisco AMP Threat Grid Sample Analysis:" 
        echo "============================================================" >> $caseFolder\ThreatGRID-results.txt
        $message >> $caseFolder\ThreatGRID-results.txt
        echo "============================================================" >> $caseFolder\ThreatGRID-results.txt
        echo "" >> $caseFolder\ThreatGRID-results.txt

        $fileHashSha256 = @($message | findstr -i "sha256").Split(":") | findstr -v SHA
        & .\Case-API.ps1 -lrhost $LogRhythmHost -command add_note -casenum $caseNumber -note "SHA256 File Hash:$fileHashSha256" -token $caseAPItoken

        $fileHashMd5 = @($message | findstr -i "md5").Split(":") | findstr -v MD5
        & .\Case-API.ps1 -lrhost $LogRhythmHost -command add_note -casenum $caseNumber -note "MD5 File Hash:$fileHashMd5" -token $caseAPItoken
        
        $sampleFileName = @($message | findstr -i "magic").Split(":") | findstr -iv magic
        & .\Case-API.ps1 -lrhost $LogRhythmHost -command add_note -casenum $caseNumber -note "Filetype:$sampleFileName" -token $caseAPItoken

        $submissionIDs = @(@($results | findstr sample).split("=") | findstr -v "sample").trim() -match '[a-f0-9]{32}'
        

    } else {
        Write-Host ""
        $messageTitle = "$risk"
        $message = @"
Cisco AMP Threat Grid Sample Analysis

Sample      :  $leSample
Threat Score:  $threatScore
Submission  :  $submitted
MD5         :  $md5
SHA1        :  $sha1
SHA256      :  $sha256
File Name   :  $fileName
File Type   :  $fileType
File Magic  :  $fileDetails
"@
        $message
        echo "" >> $caseFolder\ThreatGRID-results.txt
        echo "Cisco AMP Threat Grid Sample Analysis:" 
        echo "============================================================" >> $caseFolder\ThreatGRID-results.txt
        $message >> $caseFolder\ThreatGRID-results.txt
        echo "============================================================" >> $caseFolder\ThreatGRID-results.txt
        echo "" >> $caseFolder\ThreatGRID-results.txt
    }
}

Get-Variable | Remove-Variable -EA 0

}

ThreatGRID
type $caseFolder\ThreatGRID-results.txt >> $caseFolder\Spam-Report.txt