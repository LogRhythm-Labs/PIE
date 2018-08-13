#
# Early development of Shodan integration for PIE.  Exploritory to identify potential areas of evidence collection and risk assessment acceleration.
# Areas to add in: Reverse DNS lookup to provide list of IP addresses for Links.  This is not a threatScore modifier, but increases documentation thoroughness.
# Certificate inspection.  Initially groom to find LetsEncrypt Self-Registration certificates.  This may be a point to increase threatScore.
# Explore examination of services running on host.  Example, if identifying tor/tftp/ftp or other file delivery services found in conjuction with HTTP/HTTPS, increase threatScore.
#
# Mask errors
$ErrorActionPreference= 'continue'

$links = "google.com"

# Shodan.io
$shodan = $true
$shodanAPI = "duh deh deh deh deh duh duh duh dah duh"

if ( $shodan -eq $true ) {

    $links | ForEach-Object {
        $splitLink = ([System.Uri]"$_").Host
          
        $shodanIPQuery = iwr "https://api.shodan.io/dns/resolve?hostnames=$splitLink&key=$shodanAPI"
        $shodanIPQuery.RawContent | Out-File .\shodanIPQuery.txt
        $shodanIPInfo = Get-Content .\shodanIPQuery.txt | select -Skip 14 | ConvertFrom-Json
        $shodanIP = $shodanIPInfo.$splitLink
        $shodanHostInfo = iwr "https://api.shodan.io/shodan/host/$shodanIP`?key=$shodanAPI"
######## VOID #######
        $isitblacklisted = $shodanResults.MALWARE.NOTIFICATIONS | Select-Object -Property 'Blacklist'
        $isitcompromised = $shodanResults.MALWARE.NOTIFICATIONS | Select-Object -Property 'Websitemalware'
        #$isitblacklisted = $shodanAnalysis.Content | findstr blacklisted
        #$isitcompromised = $shodanAnalysis.Content | findstr -i compromised

        if ( $isitblacklisted.BLACKLIST -eq $true ) {
            $shodanStatus = "BLACKLISTED LINK! shodan has flagged this host: $splitLink. Full details available here: $shodanLink."
            $threatScore += 1

            & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -command add_note -casenum $caseNumber -note "$shodanStatus" -token $caseAPItoken
        } 
        if ( $isitcompromised.WEBSITEMALWARE -eq $true ) {
            $shodanStatus = "MALWARE DETECTED! shodan has flagged this host: $splitLink. Full details available here: $shodanLink."
            $threatScore += 1

            & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -command add_note -casenum $caseNumber -note "$shodanStatus" -token $caseAPItoken                    
        } else {
            $shodanStatus = "shodan has determined this link is clean. Full details available here: $shodanLink."

            & $pieFolder\plugins\Case-API.ps1 -lrhost $LogRhythmHost -command add_note -casenum $caseNumber -note "$shodanStatus" -token $caseAPItoken
        }

        echo "============================================================" >> "$caseFolder$caseID\spam-report.txt"
        echo "" >> "$caseFolder$caseID\spam-report.txt"
        echo "shodan Status:" >> "$caseFolder$caseID\spam-report.txt"
        echo "" >> "$caseFolder$caseID\spam-report.txt"
        echo $shodanStatus >> "$caseFolder$caseID\spam-report.txt"
        echo "" >> "$caseFolder$caseID\spam-report.txt"
    }
}