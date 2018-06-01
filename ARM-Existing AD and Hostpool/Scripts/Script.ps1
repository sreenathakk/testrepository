<#

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
Start-Sleep -Seconds 60
            Write-Log -Message "Downloaded DeployAgent.zip this location c:\"

#Creating a folder inside rdsh vm for extracting deployagent zip file
New-Item -Path "C:\DeployAgent" -ItemType directory -Force -ErrorAction SilentlyContinue
            Write-Log -Message "created a new folder which is 'DeployAgent' inside vm"
Expand-Archive "C:\DeployAgent.zip" -DestinationPath "C:\DeployAgent" -ErrorAction SilentlyContinue
            Write-Log -Message "Extracted the Deployagent.zip file into C:\Deployagent folder inside vm"
Set-Location "C:\DeployAgent"
            Write-Log -Message "location set the deployagent folder"

#Checking if RDInfragent is registered or not in rdsh vm
$CheckRegistery = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDInfraAgent" -ErrorAction SilentlyContinue

            Write-Log -Message "checking whether vm was registered or not"

    if($CheckRegistery){
            Write-Log -Message "VM was already registered, script execution was stopped"

        }else{

            Write-Log -Message "VM was not registered, script is going to executing"
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
    if($authentication){
        Write-Log -Message "RDMI Authentication successfully Done. Result is $authentication"  
    }else{
        Write-Log -Error "RDMI Authentication was Fail, Error: $authentication"
        
    }
    
    $HPName = Get-RdsHostPool -TenantName $TenantName -Name $HostPoolName -ErrorAction SilentlyContinue
    Write-Log -Message "Checking Hostpool is existed or not inside Tenant"

        if ($HPName) {
        
        Write-log -Message "Hostpool is existed inside tenant"
        #Exporting existed rdsregisterationinfo of hostpool
        $Registered = Export-RdsRegistrationInfo -TenantName $TenantName -HostPoolName $HostPoolName
        Write-Log -Message "Exporting Rds RegisterationInfo to variable 'registered'"
        $systemdate = (GET-DATE)
        $Tokenexpiredate = $Registered.ExpirationUtc
        $difference = $Tokenexpiredate - $systemdate
        write-log "calculating date and time whether expired or not with system time"
        if ($difference -lt 0 -or $Registered -eq 'null') {
        write-log "Registerationinfo was expired, now again creating new registeration info with hours $Hours"
            $Registered = New-RdsRegistrationInfo -TenantName $TenantName -HostPoolName $HostPoolName -ExpirationHours $Hours
        }
        #Executing DeployAgent psl file in rdsh vm and add to hostpool
        $DAgentInstall=.\DeployAgent.ps1 -ComputerName $SessionHostName -AgentInstaller ".\RDInfraAgentInstall\Microsoft.RDInfra.RDAgent.Installer-x64.msi" -SxSStackInstaller ".\RDInfraSxSStackInstall\Microsoft.RDInfra.StackSxS.Installer-x64.msi" -AdminCredentials $domaincredentials -TenantName $TenantName -PoolName $HostPoolName -RegistrationToken $Registered.Token -StartAgent $true
        Write-Log -Message "DeployAgent Script file was successfully installed inside VM $DAgentInstall"
    }

    else {
        # creating new hostpool
        $Hostpool = New-RdsHostPool -TenantName $TenantName -Name $HostPoolName -Description $Description -FriendlyName $FriendlyName
        Write-Log -Message "Successfully created new Hostpool $hostpool.name"
        #Registering hostpool with 365 days
        
        Write-log "Creating new registeration info for hostpool with expired hours $Hours"
        $ToRegister = New-RdsRegistrationInfo -TenantName $TenantName -HostPoolName $HostPoolName -ExpirationHours $Hours
        Write-Log "Successfully registered $HostPoolName, expiration date: $ToRegister.ExpirationUtc"
        
        #Executing DeployAgent psl file in rdsh vm and add to hostpool
        .\DeployAgent.ps1 -ComputerName $SessionHostName -AgentInstaller ".\RDInfraAgentInstall\Microsoft.RDInfra.RDAgent.Installer-x64.msi" -SxSStackInstaller ".\RDInfraSxSStackInstall\Microsoft.RDInfra.StackSxS.Installer-x64.msi" -AdminCredentials $domaincredentials -TenantName $TenantName -PoolName $HostPoolName -RegistrationToken $ToRegister.Token -StartAgent $true
        
        Write-Log -Message "DeployAgent Script file was successfully installed inside VM $DAgentInstall"
    }
    #add rdsh vm to hostpool
    Set-RdsSessionHost -TenantName $TenantName -HostPoolName $HostPoolName -Name $SessionHostName -AllowNewSession $true -MaxSessionLimit $MaxSessionLimit
    Write-Log -Message "added $sessionhostname  to $HostPoolName successfully"
}
}
catch{
    Write-Error -Error $_.Exception.Message

}

