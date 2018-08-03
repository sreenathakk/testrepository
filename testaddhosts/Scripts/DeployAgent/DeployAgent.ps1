<#
.SYNOPSIS
Deploys RD Infra agent into target VM

.DESCRIPTION
This script will get the registration token for the target pool name, copy the installer into target VM and execute the installer with the registration token and broker URI

If the pool name is not specified it will retreive first one (treat this as random) from the deployment.

.PARAMETER ComputerName
Required the FQDN or IP of target VM

.PARAMETER AgentInstaller
Required path to MSI installer file

.PARAMETER AgentBootServiceInstaller
Required path to MSI installer file

.PARAMETER SxSStackInstaller
Required path to MSI SxS stack installer file

.PARAMETER InitializeDBSecret
Required secret to bypass authentication of token generation API's till we have proper auth in management layer

.PARAMETER Session
Optional Powershell session into target VM

.PARAMETER AdminCredentials
Optional admin credentials that will be used to create remote powershell session to the VM

.PARAMETER $AdministratorUsername
Optional Administrator username that will be used to create remote powershell session to the VM

.PARAMETER $AdministratorLoginPassword
Optional Administrator password that will be used to create remote powershell session to the VM

.PARAMETER PoolName
Unique Pool name from which we need to get registration token

.PARAMETER StartAgent
Start the agent service (RdInfraAgent) immediately

.EXAMPLE

.\DeployAgent.ps1 -Computername 127.0.0.1 -AdministratorUsername "testadmin" -InitializeDBSecret "02C698A8-12D6-4869-AFF8-9C3149C149D0" -AgentInstaller 'Microsoft.RDInfra.RDAgent.Installer-x64' -SxSStackInstaller 
#>
#Requires -Version 4.0

Param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ComputerName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$AgentInstaller,
    
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$AgentBootServiceInstaller,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SxSStackInstaller,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$InitializeDBSecret,

    [Parameter(Mandatory=$False)]
    [System.Management.Automation.Runspaces.PSSession]$Session,

    [Parameter(Mandatory=$False)]
    [PSCredential] $AdminCredentials,

    [Parameter(Mandatory=$False, ParameterSetName='AdminCreds')]
    [String] $AdministratorUsername,
    [Parameter(Mandatory=$False, ParameterSetName='AdminCreds')]
    [SecureString] $AdministratorLoginPassword,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$TenantName,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$PoolName,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$RegistrationToken,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [bool]$StartAgent

)

function Test-IsAdmin {
    ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
}

# this will allow powershell connecting to the remote VM
if (Test-IsAdmin)
{
    Set-Item -Force -Verbose WSMan:\localhost\Client\TrustedHosts $ComputerName
}

# Convert relative paths to absolute paths if needed
$AgentBootServiceInstaller = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, $AgentBootServiceInstaller))
if ((-not $AgentBootServiceInstaller) -or (-not (Test-Path $AgentBootServiceInstaller)))
{
    throw "RD Infra Agent Installer package is not found '$AgentBootServiceInstaller'"
}

# Convert relative paths to absolute paths if needed
$AgentInstaller = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, $AgentInstaller))
if ((-not $AgentInstaller) -or (-not (Test-Path $AgentInstaller)))
{
    throw "RD Infra Agent Installer package is not found '$AgentInstaller'"
}


# Convert relative paths to absolute paths if needed
$SxSStackInstaller = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, $SxSStackInstaller))
if ((-not $SxSStackInstaller) -or (-not (Test-Path $SxSStackInstaller)))
{
    throw "SxS Stack Installer package is not found '$SxSStackInstaller'"
}


Write-Output "Creating session to VM..."
if (!$Session) {
    if (!$AdminCredentials){
        if ($AdministratorUsername -and $AdministratorLoginPassword)
        {
            $AdminCredentials = New-Object System.Management.Automation.PSCredential ($AdministratorUsername, $AdministratorLoginPassword)
        } elseif ($AdministratorUsername)
        {
            $AdminCredentials = Get-Credential -Message "Enter credentials for admin user to '$ComputerName'" -UserName $AdministratorUsername
        } else
        {
            $AdminCredentials = Get-Credential -Message "Enter credentials for admin user to '$ComputerName'" -UserName "~\Administrator"
        }
    }

    if (!$AdminCredentials){
        throw "Administrator credentials to Windows Server Core VM are not specified"
    }

    $Session = New-PSSession –ComputerName $ComputerName -Credential $AdminCredentials
}

if (!$Session) {
    throw "cannot create session to target VM"
}

if (!$RegistrationToken)
{

    if (!$PoolName -or !$TenantName)
    {
        throw "Need either RegistrationToken or Tenant/Pool names specified"
    }

    Write-Output "Query broker for the registration token 'New-RdsRegistrationInfo'"
    $registrationInfo = New-RdsRegistrationInfo $TenantName $PoolName
    $RegistrationToken = $registrationInfo.Token
    Write-Output ("Got token: " + $RegistrationToken.Substring(0,20) + "...")
}

if (!$RegistrationToken)
{
    throw "No registration token specified"
}

$bootloader_installer_package_filename = [System.IO.Path]::GetFileName($AgentBootServiceInstaller)
$agent_installer_package_filename = [System.IO.Path]::GetFileName($AgentInstaller)
$sxsstack_installer_package_filename = [System.IO.Path]::GetFileName($SxSStackInstaller)

$vm_download_folder = Invoke-Command -Session $Session { [System.IO.Path]::GetTempPath() }

$vm_bootloader_deploy_path = Join-Path -path $vm_download_folder -childpath $bootloader_installer_package_filename
$vm_agent_deploy_path = Join-Path -path $vm_download_folder -childpath $agent_installer_package_filename
$vm_sxsstack_deploy_path = Join-Path -path $vm_download_folder -childpath $sxsstack_installer_package_filename

Write-Host "Copy AgentBootLoader Installer into VM '$vm_bootloader_deploy_path' ..."
Copy-Item $AgentBootServiceInstaller $vm_download_folder -ToSession $Session -Force
if(-not $?)
{
    $err = "Copy AgentBootLoader installer into VM Failed!"
    write-warning $err
    throw $err
}

Write-Host "Copy Agent Installer into VM '$vm_agent_deploy_path' ..."
Copy-Item $AgentInstaller $vm_download_folder -ToSession $Session -Force
if(-not $?)
{
    $err = "Copy agent installer into VM Failed!"
    write-warning $err
    throw $err
}

Write-Host "Copy SxS Stack Installer into VM '$vm_sxsstack_deploy_path' ..."
Copy-Item $SxSStackInstaller $vm_download_folder -ToSession $Session -Force

if(-not $?)
{
    $err = "Copy SxS Stack installer into VM Failed!"
    write-warning $err
    throw $err
}

Invoke-Command -Session $Session -scriptblock {

    #uninstall old packages

    Write-Output "Uninstalling any previous versions of RDAgentBootLoader on VM"
    $bootloader_uninstall_status = Start-Process -FilePath "msiexec.exe" -ArgumentList "/x {A38EE409-424D-4A0D-B5B6-5D66F20F62A5}", "/quiet", "/qn", "/norestart", "/passive", "/l* C:\Users\AgentBootLoaderInstall.txt" -Wait -Passthru
    $sts = $bootloader_uninstall_status.ExitCode
    Write-Output "Uninstalling RD Infra Agent on VM Complete. Exit code=$sts"
    
    Write-Output "Uninstalling any previous versions of RD Infra Agent on VM"
    $legacy_agent_uninstall_status = Start-Process -FilePath "msiexec.exe" -ArgumentList "/x {5389488F-551D-4965-9383-E91F27A9F217}", "/quiet", "/qn", "/norestart", "/passive", "/l* C:\Users\AgentUninstall.txt" -Wait -Passthru
    $sts = $legacy_agent_uninstall_status.ExitCode
    Write-Output "Uninstalling RD Infra Agent on VM Complete. Exit code=$sts"
        
    Write-Output "Uninstalling any previous versions of RD Infra Agent DLL on VM"
    $agent_uninstall_status = Start-Process -FilePath "msiexec.exe" -ArgumentList "/x {CB1B8450-4A67-4628-93D3-907DE29BF78C}", "/quiet", "/qn", "/norestart", "/passive", "/l* C:\Users\AgentUninstall.txt" -Wait -Passthru
    $sts = $agent_uninstall_status.ExitCode
    Write-Output "Uninstalling RD Infra Agent on VM Complete. Exit code=$sts"    

    #install the package
    Write-Output "Installing RDAgent BootLoader on VM $using:vm_bootloader_deploy_path"

    $bootloader_deploy_status = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i $using:vm_bootloader_deploy_path", "/quiet", "/qn", "/norestart", "/passive", "/l* C:\Users\AgentBootLoaderInstall.txt" -Wait -Passthru
    $sts = $bootloader_deploy_status.ExitCode
    Write-Output "Installing RDAgentBootLoader on VM Complete. Exit code=$sts"

    #install the package
    Write-Output "Installing RD Infra Agent on VM $using:vm_agent_deploy_path"

    $agent_deploy_status = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i $using:vm_agent_deploy_path", "/quiet", "/qn", "/norestart", "/passive", "REGISTRATIONTOKEN=$using:RegistrationToken", "/l* C:\Users\AgentInstall.txt" -Wait -Passthru
    $sts = $agent_deploy_status.ExitCode
    Write-Output "Installing RD Infra Agent on VM Complete. Exit code=$sts"
        

    if ($using:StartAgent)
    {
        write-output "Starting service"
        Start-Service RDAgentBootLoader
    }

    #delete the installer
    Remove-Item -Path $using:vm_agent_deploy_path -Force -Recurse | Out-Null
}

$agent_deploy_status = Invoke-Command -Session $Session { $agent_deploy_status.ExitCode }


Invoke-Command -Session $Session -scriptblock {

    #uninstall old package

    #Write-Output "Uninstalling any previous versions of SxS Stack on VM"
    #$agent_uninstall_status = Start-Process -FilePath "msiexec.exe" -ArgumentList "/x {5389488F-551D-4965-9383-E91F27A9F217}", "/quiet", "/qn", "/norestart", "/passive", "/l* C:\Users\WebDeployLog.txt" -Wait -Passthru
    #$sts = $agent_uninstall_status.ExitCode
    #Write-Output "Uninstalling RD Infra Agent on VM Complete. Exit code=$sts"

    #install the package
    Write-Output "Installing SxS Stack on VM $using:vm_sxsstack_deploy_path"

    $sxsstack_deploy_status = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i $using:vm_sxsstack_deploy_path", "/quiet", "/qn", "/norestart", "/passive", "/l* C:\Users\SxSInstall.txt" -Wait -Passthru
    $sts = $sxsstack_deploy_status.ExitCode
    Write-Output "Installing RD SxS Stack on VM Complete. Exit code=$sts"


    #delete the installer
    Remove-Item -Path $using:vm_sxsstack_deploy_path -Force -Recurse | Out-Null
}

$sxsstack_deploy_status = Invoke-Command -Session $Session { $sxsstack_deploy_status.ExitCode }


$Session | Remove-PSSession -WhatIf:$False
