﻿
Param(
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [string] $RdbrokerURI,

    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string] $fileURI,

    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [string] $TenantName,

    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [string] $AadTenantId,

    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string] $FriendlyName,

    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string] $Description,

    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [string] $HostPoolName,

    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string] $HostPoolFriendlyName,

    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string] $HostPoolDescription,
         
    [Parameter(Mandatory=$True)]
    [String] $Username,
    [Parameter(Mandatory=$True)]
    [string] $Password,
    [Parameter(Mandatory=$True)]
    [string] $ResourceGroupName


  
)


Invoke-WebRequest -Uri $fileURI -OutFile "C:\PowershellModules.zip"
Start-Sleep -Seconds 45
Expand-Archive "C:\PowershellModules.zip" -DestinationPath "C:\"
Import-Module "C:\PowershellModules\Microsoft.RDInfra.RDPowershell.dll"
$SecurePass = $Password | ConvertTo-SecureString -asPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential($Username,$SecurePass)
Set-RdsContext -DeploymentUrl $RdbrokerURI -Credential $Credential
$newRdsTenant=New-RdsTenant -Name $TenantName -AadTenantId $AadTenantId -FriendlyName $FriendlyName -Description $Description
$newRDSHostPool=New-RdsHostPool -TenantName $TenantName  -Name $HostPoolName -Description $HostPoolDescription -FriendlyName $HostPoolFriendlyName
<#
Start-Sleep -Seconds 60
Remove-Item -Path "C:\PowershellModules.zip" -Recurse -force
Remove-Item -Path "C:\PowershellModules" -Recurse -Force
#>

$Securepass=ConvertTo-SecureString -String $Password -AsPlainText -Force
$Azurecred=New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList($Username, $Securepass)
Install-Module -Name AzureRM.Profile -AllowClobber -Force
Install-Module -Name AzureRM.Compute -AllowClobber -Force
Import-Module -Name AzureRM.Profile
Import-Module -Name AzureRM.Compute

$login=Login-AzureRmAccount -Credential $Azurecred -TenantId $AadTenantId

$ResourceGroup=Get-AzureRmResourceGroup -Name $ResourceGroupName
if($ResourceGroup){
Remove-AzureRmResourceGroup -Name $ResourceGroupName -Force
}



   $a = new-object -comobject wscript.shell

   $a.Popup("Do you want to choose Yes or No?", 0,"Confirmation",4)