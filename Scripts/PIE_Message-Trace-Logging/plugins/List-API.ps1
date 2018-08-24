
  #====================================#
  #       List API - 7.3.x +           #
  # LogRhythm Labs                     #
  # greg . foss @ logrhythm . com      #
  # v1.0  --  August, 2018             #
  #====================================#

# Copyright 2018 LogRhythm Inc.   
# Licensed under the MIT License. See LICENSE file in the project root for full license information.

# ================================================================================
# LogRhythm List Management
# ================================================================================

param ( [string]$lrhost,
        [string]$token,
        [string]$listDetail,
        [string]$appendToList,
        [string]$removeFromList,
        [string]$listName,
        [string]$listContents,
        [switch]$getLists,
        [switch]$listTags )

# ================================================================================
# Global Parameters
# ================================================================================

# Mask errors
$ErrorActionPreference= 'silentlycontinue'

$token = "Bearer $token"
$adminURL = "https://$lrhost/lr-admin-api"
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-type", "application/json")
$headers.Add("Authorization", $token)
$headers.Add("pageSize", "1000")
$headers.Add("maxItemsThreshold", "1000")

#force TLS v1.2 required by caseAPI
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#Ignore invalid SSL certification warning
add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

#Get the date/time
$date = Get-Date


# ================================================================================
# List of Lists!
# ================================================================================  

if ( $getLists ) {
    $listURL = "$adminURL/lists/"
    $output = irm -Uri $listURL -Headers $headers -Method GET
    $output | Select-Object * | Out-GridView
    break;
}


# ================================================================================
# Obtain the Details of a List
# ================================================================================  

if ( $listDetail ) {
    Write-Host ""
    Write-Host "List Detail" -ForegroundColor Green
    Write-Host "================================"

    $listURL = "$adminURL/lists/"
    $output = irm -Uri $listURL -Headers $headers -Method GET
    $output | Where-Object name -EQ "$listDetail"

    Write-Host "================================"
    Write-Host ""
    break;
}


# ================================================================================
# List the Contents of a List
# ================================================================================  

if ( $listContents ) {
    
    Write-Host ""
    Write-Host "List Items" -ForegroundColor Green
    Write-Host "================================"

    $listURL = "$adminURL/lists/"
    $output = irm -Uri $listURL -Headers $headers -Method GET
    $listGuid = @($output | Where-Object name -EQ "$listContents").guid
        
    $listContentData = $listURL + $listGuid + "/"
    $output = irm -Uri $listContentData -Headers $headers -Method GET
    
    if ( $output.items.count -gt 0 ) {
        $output.items.value
    } else {
        Write-Host "List " -NoNewline -ForegroundColor Red
        Write-Host "$listContents" -NoNewline
        Write-Host " contains no data..." -ForegroundColor Red
    }

    Write-Host "================================"
    Write-Host ""
    break;
}


# ================================================================================
# Append to List
# ================================================================================  

if ( $appendToList ) {
    
    if ( $listName ) {
        
        Write-Host ""
        Write-Host "Append to List " -NoNewline -ForegroundColor Green
        Write-Host "$listName"
        Write-Host "================================"

        $listURL = "$adminURL/lists/"
        $output = irm -Uri $listURL -Headers $headers -Method GET
        $listGuid = @($output | Where-Object name -EQ "$listName").guid
        $listType = @($output | Where-Object name -EQ "$listName").listType

        $listUpdate = $listURL + $listGuid + "/items"
        
        # ListItemType: List,KnownService,Classification,CommonEvent,KnownHost,IP,IPRange,Location,MsgSource,
        # MsgSourceType,MPERule,Network,StringValue,Port,PortRange,Protocol,HostName,ADGroup,Entity,RootEntity,
        # DomainOrigin,Hash,Policy,VendorInfo,Result,ObjectType,CVE,UserAgent,ParentProcessId,ParentProcessName,
        # ParentProcessPath,SerialNumber,Reason,Status,ThreatId,ThreatName,SessionType,Action,ResponseCode,Identity

        $payload = @('{ "items": 
[
{
    "displayValue": "List",
    "expirationDate": null,
    "isExpired": false,
    "isListItem": false,
    "isPattern": false,
    "listItemDataType": "List",
    "listItemType": "' + $listType + '",
    "value": "' + $appendToList + '",
    "valueAsListReference": {}
}
]}')
        try {
            
            $output = Invoke-RestMethod -Uri $listUpdate -Headers $headers -Method POST -Body $payload

            Write-Host "Successfully Appended " -NoNewline
            Write-Host "$appendToList" -NoNewline -ForegroundColor Cyan
            Write-Host " To List " -NoNewline
            Write-Host "$listName"-ForegroundColor Cyan

        } catch {
            
            Write-Host "Failed To Append " -ForegroundColor Red -NoNewline
            Write-Host "$appendToList" -NoNewline -ForegroundColor Cyan
            Write-Host " To List " -NoNewline -ForegroundColor Red
            Write-Host "$listName"-ForegroundColor Cyan
        }

        Write-Host "================================"
        Write-Host ""
        break;

    } else {
        Write-Host "How am I supposed to update a case without a list to populate? (use -listName)" -ForegroundColor Red
        break;
    }
}


# ================================================================================
# Remove From List
# ================================================================================    

if ( $removeFromList ) {
    
    if ( $listName ) {
        
        Write-Host ""
        Write-Host "Remove From List " -NoNewline -ForegroundColor Red
        Write-Host "$listName"
        Write-Host "================================"

        $listURL = "$adminURL/lists/"
        $output = irm -Uri $listURL -Headers $headers -Method GET
        $listGuid = @($output | Where-Object name -EQ "$listName").guid
        $listType = @($output | Where-Object name -EQ "$listName").listType

        $listUpdate = $listURL + $listGuid + "/items"

        $payload = @('{ "items": 
[
{
    "displayValue": "List",
    "expirationDate": null,
    "isExpired": false,
    "isListItem": false,
    "isPattern": false,
    "listItemDataType": "List",
    "listItemType": "' + $listType + '",
    "value": "' + $removeFromList + '",
    "valueAsListReference": {}
}
]}')
        try {
            
            $output = Invoke-RestMethod -Uri $listUpdate -Headers $headers -Method DELETE -Body $payload

            Write-Host "Successfully Removed " -NoNewline
            Write-Host "$removeFromList" -NoNewline -ForegroundColor Cyan
            Write-Host " From List " -NoNewline
            Write-Host "$listName" -ForegroundColor Cyan

        } catch {
            
            Write-Host "Failed To Remove " -ForegroundColor Red -NoNewline
            Write-Host "$appendToList" -NoNewline -ForegroundColor Cyan
            Write-Host " From List " -NoNewline -ForegroundColor Red
            Write-Host "$listName"-ForegroundColor Cyan
            Write-Error
        }

        Write-Host "================================"
        Write-Host ""
        break;

    } else {
        Write-Host "How am I supposed to update a list without a list to populate? (use -listName)" -ForegroundColor Red
        break;
    }
}

# Clear all variables
Get-Variable | Remove-Variable -EA 0
