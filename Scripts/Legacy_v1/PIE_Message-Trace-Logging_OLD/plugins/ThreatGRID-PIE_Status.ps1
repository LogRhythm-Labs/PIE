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

function Get-ThreatGridSampleStatus {
    param(		
	    [Parameter(Mandatory=$True)] [string] $ApiKey,
	    [Parameter(Mandatory=$True)] [string] $SampleId,
        [string]$caseNumber,
        [string]$caseFolder,
        [string]$LogRhythmHost,
        [string]$caseAPItoken,
	    [int] $TotalResponses = 0
    )

    sleep 60

    $Uri = "https://panacea.threatgrid.com/api/v2/samples/${SampleId}?api_key=${ApiKey}"

    try {
	    # Call Threat Grid
	    $Response = Invoke-RestMethod -Uri $Uri -method GET 
        $statusUpdate = $Response.data.status
		
	    # Possible Statuses
	    switch ($Response.data.state)
	    {
		    "fail" {
			    write-host "Failed" $SampleId "due to reason" $Response.data.status
			    return $false
                if ( $caseAPItoken ) {
                    $caseUpdate = "Cisco AMP Threat Grid was unable to analyze this file due to $statusUpdate"
                    echo $caseUpdate
                    & .\Case-API.ps1 -lrhost $LogRhythmHost -command add_note -casenum $caseNumber -note "$caseUpdate" -token $caseAPItoken
                }
		    }	

		    "wait" {
			    # Do what it says!
		    }

		    "run" {
			    # RUN!
		    }
   
            "proc" {
                # It's doin stuff
            }

		    "succ" {
			    write-host "Successfully analyzed" $SampleId
			    return $true
                if ( $caseAPItoken ) {
                    $caseUpdate = "Cisco AMP Threat Grid analysis complete - view the full details here: https://panacea.threatgrid.com/mask/#/submission/$SampleId"
                    echo $caseUpdate
                    & .\Case-API.ps1 -lrhost $LogRhythmHost -command add_note -casenum $caseNumber -note "$caseUpdate" -token $caseAPItoken
                }
		    }

		    default {
			    write-host "Received unknown state from Threat Grid" $Response.data.state
		    }	
	    }
	    # Job is not done yet
	    # Check status again
	    $TotalResponses += 1

	    # Default to 60 second delay
	    $sleep = 60

	    if ($TotalResponses -gt 20)
	    {
		    # This is 20 minutes so it should have done something by now.
		    write-host "Hit maximum retry limit" $TotalResponses "for sample" $SampleId
		    return $false
	    } 
		
	    start-sleep -s $sleep
	    write-host "Job not yet done, checking again in" $sleep "seconds. Attempt" $TotalResponses
			
	    return (Get-ThreatGridSampleStatus -ApiKey $ApiKey -SampleId $SampleId -TotalResponses $TotalResponses)
    }
    catch {
	    # Oh no, it failed!
	    write-host "Failed to get Threat Grid Sample Status" $SampleId
	    write-host $_.Exception
	    return $null
        if ( $caseAPItoken ) {
            $caseUpdate = "Cisco AMP Threat Grid was unable to analyze this file due to " + $_.Exception
            echo $caseUpdate
            & .\Case-API.ps1 -lrhost $LogRhythmHost -command add_note -casenum $caseNumber -note "$caseUpdate" -token $caseAPItoken
        }
    }

}

Get-ThreatGridSampleStatus -ApiKey $ApiKey -SampleId $SampleId
