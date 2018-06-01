﻿<#

.SYNOPSIS
Creating Session Hosts and add to existing domain and existing/new Hostpool.

.DESCRIPTION
This script creates new session host servers, add to existing domain and existing/new Hostpool
The supported Operating Systems Windows Server 2016.

.ROLE
Readers

#>


param(
    [Parameter(mandatory = $true)]
    [string]$RDBrokerURL,

    [Parameter(mandatory = $true)]
    [string]$TenantName,

    [Parameter(mandatory = $true)]
    [string]$HostPoolName,

    [Parameter(mandatory = $false)]
    [string]$Description,


    [Parameter(mandatory = $false)]
    [string]$FriendlyName,


    [Parameter(mandatory = $true)]
    [int]$MaxSessionLimit,

    [Parameter(mandatory = $true)]
    [string]$Hours,

    [Parameter(mandatory = $true)]
    [string]$FileURI,

    [Parameter(mandatory = $true)]
    [string]$DelegateAdminUsername,

    [Parameter(mandatory = $true)]
    [string]$DelegateAdminpassword,


    [Parameter(mandatory = $true)]
    [string]$DomainAdminUsername,

    [Parameter(mandatory = $true)]
    [string]$DomainAdminPassword
)



function Write-Log 
{ 
    [CmdletBinding()] 
    param ( 
        [Parameter(Mandatory=$false)] 
        [string]$Message,
        [Parameter(Mandatory=$false)] 
        [string]$Error 
    ) 
     
    try 
    { 
        $DateTime = Get-Date -Format ‘MM-dd-yy HH:mm:ss’ 
        $Invocation = "$($MyInvocation.MyCommand.Source):$($MyInvocation.ScriptLineNumber)" 
        if($Message){
        Add-Content -Value "$DateTime - $Invocation - $Message" -Path "$([environment]::GetEnvironmentVariable('TEMP', 'Machine'))\ScriptLog.log" 
        }else{
        Add-Content -Value "$DateTime - $Invocation - $Error" -Path "$([environment]::GetEnvironmentVariable('TEMP', 'Machine'))\ScriptLog.log" 
        }
    } 
    catch 
    { 
        Write-Error $_.Exception.Message 
    } 
}





try{
#Downloading the DeployAgent zip file to rdsh vm
Invoke-WebRequest -Uri $fileURI -OutFile "C:\DeployAgent.zip"
Start-Sleep -Seconds 25
            Write-Log -Message "Downloaded DeployAgent.zip into this location c:\"

#Creating a folder inside rdsh vm for extracting deployagent zip file
New-Item -Path "C:\DeployAgent" -ItemType directory -Force -ErrorAction SilentlyContinue
            Write-Log -Message "Created a new folder which is 'DeployAgent' inside VM"
Expand-Archive "C:\DeployAgent.zip" -DestinationPath "C:\DeployAgent" -ErrorAction SilentlyContinue
            Write-Log -Message "Extracted the 'Deployagent.zip' file into 'C:\Deployagent' folder inside VM"
Set-Location "C:\DeployAgent"
            Write-Log -Message "set the location to deployagent folder"

#Checking if RDInfragent is registered or not in rdsh vm
$CheckRegistery = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDInfraAgent" -ErrorAction SilentlyContinue

            Write-Log -Message "Checking whether VM was Registered with RDInfraAgent or not"

    if($CheckRegistery){
            Write-Log -Message "VM was already registered with RDInfraAgent, script execution was stopped"

        }else{

            Write-Log -Message "VM was not registered with RDInfraAgent, script is executing"
            }
#Getting fqdn of rdsh vm

if (!$CheckRegistery) {
    #Importing RDMI PowerShell module
    
    Import-Module .\PowershellModules\Microsoft.RDInfra.RDPowershell.dll
            Write-Log -Message "Imported RDMI powershell modules successfully"
    $Securepass = ConvertTo-SecureString -String $DelegateAdminpassword -AsPlainText -Force
    $Credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($DelegateAdminUsername, $Securepass)
    $DAdminSecurepass = ConvertTo-SecureString -String $DomainAdminPassword -AsPlainText -Force
    $domaincredentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($DomainAdminUsername, $DAdminSecurepass)
    $SessionHostName = (Get-WmiObject win32_computersystem).DNSHostName + "." + (Get-WmiObject win32_computersystem).Domain
            Write-Log  -Message "Fully qualified domain name of VM $SessionHostName"
    
    #Setting RDS Context
    $authentication=Set-RdsContext -DeploymentUrl $RDBrokerURL -Credential $Credentials
    $obj=$authentication | Out-String
    if($authentication){
        Write-Log -Message "RDMI Authentication successfully Done. Result: `
       $obj"  
    }else{
        Write-Log -Error "RDMI Authentication Failed, Error: `
       $obj"
        
    }
    
    $HPName = Get-RdsHostPool -TenantName $TenantName -Name $HostPoolName -ErrorAction SilentlyContinue
    Write-Log -Message "Checking Hostpool is existing or not inside the Tenant"

        if ($HPName) {
        Write-log -Message "Hostpool is existing inside the tenant"

        Write-Log -Message "Checking Hostpool UseResversconnect is true or false"
          # Cheking UseReverseConnect is true or false
        if($HPName.UseReverseConnect -eq $False)
        {
        Write-Log -Message "Usereverseconnect is false, it will be changed to true"
            Set-RdsHostPool -TenantName $TenantName -Name $HostPoolName -UseReverseConnect $true
        }

        #Exporting existed rdsregisterationinfo of hostpool
        $Registered = Export-RdsRegistrationInfo -TenantName $TenantName -HostPoolName $HostPoolName
        $reglog=$registered | Out-String
        Write-Log -Message "Exporting Rds RegisterationInfo to variable $reglog'"
        $systemdate = (GET-DATE)
        $Tokenexpiredate = $Registered.ExpirationUtc
        $difference = $Tokenexpiredate - $systemdate
        write-log "calculating date and time whether expired or not with system time"
        if ($difference -lt 0 -or $Registered -eq 'null') {
        write-log "Registerationinfo was expired, now again creating new registeration info with hours $Hours"
            $Registered = New-RdsRegistrationInfo -TenantName $TenantName -HostPoolName $HostPoolName -ExpirationHours $Hours
        }else{
        $reglogexpired=$Tokenexpiredate | Out-String
        Write-Log "Registerationinfo is not expired, expired in $reglogexpired"
        }
        #Executing DeployAgent psl file in rdsh vm and add to hostpool
        $DAgentInstall=.\DeployAgent.ps1 -ComputerName $SessionHostName -AgentInstaller ".\RDInfraAgentInstall\Microsoft.RDInfra.RDAgent.Installer-x64.msi" -SxSStackInstaller ".\RDInfraSxSStackInstall\Microsoft.RDInfra.StackSxS.Installer-x64.msi" -AdminCredentials $domaincredentials -TenantName $TenantName -PoolName $HostPoolName -RegistrationToken $Registered.Token -StartAgent $true
        Write-Log -Message "DeployAgent Script file was successfully installed inside VM for existing hostpool $HostPoolName `
        $DAgentInstall"
    }

    else {
        # creating new hostpool
        $Hostpool = New-RdsHostPool -TenantName $TenantName -Name $HostPoolName -Description $Description -FriendlyName $FriendlyName
        $HName=$hostpool.name | outstring
        Write-Log -Message "Successfully created new Hostpool $HName"
        
        # setting up usereverseconnect as true
        Write-Log -Message "set the UserReverseconnect value as true"
        Set-RdsHostPool -TenantName $TenantName -Name $HostPoolName -UseReverseConnect $true
        
        
        #Registering hostpool with 365 days
        Write-log "Creating new registeration info for hostpool with expired hours $Hours"
        $ToRegister = New-RdsRegistrationInfo -TenantName $TenantName -HostPoolName $HostPoolName -ExpirationHours $Hours
        Write-Log "Successfully registered $HostPoolName, expiration date: $ToRegister.ExpirationUtc"
        
        #Executing DeployAgent psl file in rdsh vm and add to hostpool
        .\DeployAgent.ps1 -ComputerName $SessionHostName -AgentInstaller ".\RDInfraAgentInstall\Microsoft.RDInfra.RDAgent.Installer-x64.msi" -SxSStackInstaller ".\RDInfraSxSStackInstall\Microsoft.RDInfra.StackSxS.Installer-x64.msi" -AdminCredentials $domaincredentials -TenantName $TenantName -PoolName $HostPoolName -RegistrationToken $ToRegister.Token -StartAgent $true
        
        Write-Log -Message "DeployAgent Script file was successfully installed inside VM for new $HName `
        $DAgentInstall"
    }
    #add rdsh vm to hostpool
    $addRdsh=Set-RdsSessionHost -TenantName $TenantName -HostPoolName $HostPoolName -Name $SessionHostName -AllowNewSession $true -MaxSessionLimit $MaxSessionLimit
    $rdshName=$addRdsh.name | Out-String
    $poolName=$addRdsh.hostpoolname | Out-String
    Write-Log -Message "Successfully added '$rdshName' VM to '$poolName'"
}

Remove-Item -Path "C:\DeployAgent.zip" -Recurse -force
Remove-Item -Path "C:\DeployAgent" -Recurse -Force
}
catch{
    Write-log -Error $_.Exception.Message

}

