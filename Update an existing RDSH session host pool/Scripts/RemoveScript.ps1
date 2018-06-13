param(
    [Parameter(mandatory = $true)]
    [string]$RDBrokerURL,

    [Parameter(mandatory = $true)]
    [string]$TenantName,

    [Parameter(mandatory = $true)]
    [string]$HostPoolName,

    [Parameter(mandatory = $true)]
    [string]$DelegateAdminUsername,

    [Parameter(mandatory = $true)]
    [string]$DelegateAdminpassword,

    [Parameter(mandatory = $true)]
    [string]$SubscriptionId,

    [Parameter(mandatory = $false)]
    [string]$FileURI,

    [Parameter(mandatory = $true)]
    [string]$DomainAdminUsername,

    [Parameter(mandatory = $true)]
    [string]$DomainAdminPassword
)


    Invoke-WebRequest -Uri $fileURI -OutFile "C:\DeployAgent.zip"
    #Write-Log -Message "Downloaded DeployAgent.zip into this location C:\"

    #Creating a folder inside rdsh vm for extracting deployagent zip file
    New-Item -Path "C:\DeployAgent" -ItemType directory -Force -ErrorAction SilentlyContinue
    #Write-Log -Message "Created a new folder which is 'DeployAgent' inside VM"
    Expand-Archive "C:\DeployAgent.zip" -DestinationPath "C:\DeployAgent" -ErrorAction SilentlyContinue
   #Write-Log -Message "Extracted the 'Deployagent.zip' file into 'C:\Deployagent' folder inside VM"
    Set-Location "C:\DeployAgent"
    #Write-Log -Message "Setting up the location of Deployagent folder"

Import-Module .\PowershellModules\Microsoft.RDInfra.RDPowershell.dll

#AzureLogin Credentials
$Securepass=ConvertTo-SecureString -String $DelegateAdminpassword -AsPlainText -Force
$Credentials=New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList($DelegateAdminUsername, $Securepass)

#Domain Credentials
$DAdminSecurepass = ConvertTo-SecureString -String $DomainAdminPassword -AsPlainText -Force
$domaincredentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($DomainAdminUsername, $DAdminSecurepass)

    #Setting RDS Context
    Set-RdsContext -DeploymentUrl $RDBrokerURL -Credential $Credentials


$allshs=Get-RdsSessionHost -TenantName $tenantname -HostPoolName $HostPoolName

Function Get-RdpSessions 
{
    param(
        [string]$computername 
    )
    $result=0
    $result=@()
    $processinfo = Get-WmiObject -Query "select * from win32_process where name='explorer.exe'" -ComputerName $computername -ErrorAction SilentlyContinue
   
    foreach($process in $processinfo){
    $result+=New-Object -TypeName psobject
    $result | Add-Member -MemberType NoteProperty -Name 'Computer' -Value $computername -ErrorAction SilentlyContinue
    $result | Add-Member -MemberType NoteProperty -Name 'Loggedon' -Value $Process.GetOwner().User -ErrorAction SilentlyContinue
    $result | Add-Member -MemberType NoteProperty -Name 'Sessionid' -Value $Process.sessionid -ErrorAction SilentlyContinue
    }
    return $result
}



Function Remove-AzureRMVMInstanceResource {
 Param (
       
    # The VM name to remove, regex are supported
    [parameter(mandatory)]
    [String]$VMName
 )

    # Remove the VM's and then remove the datadisks, osdisk, NICs
    Get-AzureRmVM | Where-Object {$_.name -eq $VMName}  | foreach {
        $a=$_
        $DataDisks = @($_.StorageProfile.DataDisks.Name)
        $OSDisk = @($_.StorageProfile.OSDisk.Name)

        if ($pscmdlet.ShouldProcess("$($_.Name)", "Removing VM, Disks and NIC: $($_.Name)"))
        {
            #Write-Warning -Message "Removing VM: $($_.Name)"
            $_ | Remove-AzureRmVM -Force -Confirm:$false

            $_.NetworkProfile.NetworkInterfaces | ForEach-Object {
                $NICName = Split-Path -Path $_.ID -leaf
                #Write-Warning -Message "Removing NIC: $NICName"
                #Get-AzureRmNetworkInterface -ResourceGroupName $ResourceGroup -Name $NICName | Remove-AzureRmNetworkInterface -Force
                Get-AzureRmNetworkInterface | Where-Object {$_.Name -eq $NICName} | Remove-AzureRmNetworkInterface -Force
            }

            # Support to remove managed disks
            if($a.StorageProfile.OsDisk.ManagedDisk ) {
                ($DataDisks + $OSDisk) | ForEach-Object {
                    #Write-Warning -Message "Removing Disk: $_"
                    #Get-AzureRmDisk -ResourceGroupName $ResourceGroup -DiskName $_ | Remove-AzureRmDisk -Force
                }
            }
            # Support to remove unmanaged disks (from Storage Account Blob)
            else {
                # This assumes that OSDISK and DATADisks are on the same blob storage account
                # Modify the function if that is not the case.
                $saname = ($a.StorageProfile.OsDisk.Vhd.Uri -split '\.' | Select -First 1) -split '//' |  Select -Last 1
                $sa = Get-AzureRmStorageAccount | Where-Object {$_.StorageAccountName -eq $saname}
        
                # Remove DATA disks
                $a.StorageProfile.DataDisks | foreach {
                    $disk = $_.Vhd.Uri | Split-Path -Leaf
                    Get-AzureStorageContainer -Name vhds -Context $Sa.Context |
                    Get-AzureStorageBlob -Blob  $disk |
                    Remove-AzureStorageBlob  
                }
        
                # Remove OSDisk disk
                $disk = $a.StorageProfile.OsDisk.Vhd.Uri | Split-Path -Leaf
                Get-AzureStorageContainer -Name vhds -Context $Sa.Context |
                Get-AzureStorageBlob -Blob  $disk |
                Remove-AzureStorageBlob
                
                # Remove Boot Diagnostic
                $diagVMName=0
                $diag=$_.Name.ToLower()
                $diagVMName=$diag -replace '[\-]', ''
                $dCount=$diagVMName.Length
                            if($dCount -cgt 9){
                                $digsplt=$diagVMName.substring(0,9)
                                $diagVMName=$digsplt
                                }
                $diagContainerName = ('bootdiagnostics-{0}-{1}' -f $diagVMName, $_.VmId)
                Set-AzureRmCurrentStorageAccount -Context $sa.Context
                Remove-AzureStorageContainer -Name $diagContainerName -Force
                

            }
            # If you are on the network you can cleanup the Computer Account in AD            
	        Get-ADComputer -Identity $a.OSProfile.ComputerName | Remove-ADObject -Recursive -confirm:$false
            #Remove-DnsServerResourceRecord -ZoneName $DomainName -RRType "A" -Name $a.OSProfile.ComputerName -Force -Confirm:$false
            
        }#PSCmdlet(ShouldProcess)
    }

    
}




  try{

            $sessionusers=0
            $sessionusers=@()
                          
                $sid=Get-RdsUserSession -TenantName $tenantname -HostPoolName $HostPoolName
            
            foreach($sessionid in $sid){
            if($sessionid.UserPrincipalname -ne $null){
            $UPname=$sessionid.UserPrincipalname
            $sessionusers+=$UPname.split("\")[1]
            #$sessionusers
            }
            }


        $computers=0
        $computers=@()

        #Sending message to who are logged on 
        foreach($shs in $allshs){
                        $shsname=$shs.Name
                        $allsessions=$shs.sessions

        $cim=Get-RdpSessions -computername $shsname

        if(!$cim){
                    $computers+=$shsname
                }
                else
                {
                 foreach($ci in $cim)
                 {
                   foreach($user in $ci.Loggedon){
                        #$user
                        
                        if($user -in $sessionusers){
                        
                        $computers+=$ci.computer
                        
                        #Send-RdsUserSessionMessage -TenantName $tenantname -HostPoolName $HostPoolName -SessionHostName $ci.computer -SessionId $ci.Sessionid -MessageTitle $MessageTitle -MessageBody $MessageBody -NoConfirm $false -ErrorAction SilentlyContinue
                        }
                      }
                  }
               }
            }

    
    $allcomputers=$computers | select -Unique
    
                        #Get Domaincontroller VMname


                        $DName=Get-ADDomainController
                        $DControllerVM=$DName.Name
                        $ZoneName=$DName.Forest
                
                do{
                        Write-Output "checking nuget package existed or not"
                        if (!(Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue -ListAvailable)) 
                        {
                        Write-Output "installing nuget package inside vm: $env:COMPUTERNAME"
                            Install-PackageProvider -Name nuget -Force
                        }
                        
                        $LoadModule=Get-Module -ListAvailable "Azure*"
                        
                        if(!$LoadModule){
                        Write-Output "installing azureModule inside vm: $env:COMPUTERNAME"
                        Install-Module AzureRm -AllowClobber -Force
                        }
                        } until($LoadModule)
            #Import-Module AzureRM.Resources
            #Import-Module Azurerm
            $AzSecurepass=ConvertTo-SecureString -String $DelegateAdminpassword -AsPlainText -Force
            $AzCredentials=New-Object System.Management.Automation.PSCredential($DelegateAdminUsername, $AzSecurepass)
            $loginResult=Login-AzureRmAccount -SubscriptionId $SubscriptionId  -Credential $AzCredentials
            if ($loginResult.Context.Subscription.Id -eq $SubscriptionId)
            {
                 $success=$true
            }
            else 
            {
                 throw "Subscription Id $SubscriptionId not in context"
            }
            
            
            foreach($sh in $allcomputers){
                
                # setting rdsh vm in drain mode
                Set-RdsSessionHost -TenantName $tenantname -HostPoolName $HostPoolName -Name $sh -AllowNewSession $false
                
                #Start-Sleep -Seconds 900
                
                Remove-RdsSessionHost -TenantName $tenantname -HostPoolName $HostPoolName -Name $sh -Force $true
                
                $VMName=$sh.Split(".")[0]
                $avset=Get-AzureRmVM | where-object {$_.Name -eq $VMName} | select-Object {$_.AvailabilitySetReference.Id}
                                
                Remove-AzureRMVMInstanceResource -VMName $VMName

                #$removeVM
                Invoke-Command -ComputerName $DControllerVM -Credential $domaincredentials -ScriptBlock{
                Param($ZoneName,$VMName)
                Remove-DnsServerResourceRecord -ZoneName $ZoneName -RRType "A" -Name $VMName -Force -Confirm:$false
                } -ArgumentList($ZoneName,$VMName)
                }
                Remove-AzureRmResource -ResourceId $avset.'$_.AvailabilitySetReference.Id' -Force

    }
        catch{


            }

$allHosts=Get-RdsSessionHost -TenantName $tenantname -HostPoolName $HostPoolName
if(!$allHosts){
$CheckRegistery = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDInfraAgent" -ErrorAction SilentlyContinue
if (!$CheckRegistery) {
$HPName = Get-RdsHostPool -TenantName $TenantName -Name $HostPoolName -ErrorAction SilentlyContinue
if ($HPName) {
if ($HPName.UseReverseConnect -eq $False) {
                
                Set-RdsHostPool -TenantName $TenantName -Name $HostPoolName -UseReverseConnect $true
            }

}
$SessionHostName = (Get-WmiObject win32_computersystem).DNSHostName + "." + (Get-WmiObject win32_computersystem).Domain
$Registered = Export-RdsRegistrationInfo -TenantName $TenantName -HostPoolName $HostPoolName
$systemdate = (GET-DATE)
            $Tokenexpiredate = $Registered.ExpirationUtc
            $difference = $Tokenexpiredate - $systemdate
            
            if ($difference -lt 0 -or $Registered -eq 'null') {
                
                $Registered = New-RdsRegistrationInfo -TenantName $TenantName -HostPoolName $HostPoolName -ExpirationHours $Hours
            }

            $DAgentInstall = .\DeployAgent.ps1 -ComputerName $SessionHostName -AgentInstaller ".\RDInfraAgentInstall\Microsoft.RDInfra.RDAgent.Installer-x64.msi" -SxSStackInstaller ".\RDInfraSxSStackInstall\Microsoft.RDInfra.StackSxS.Installer-x64.msi" -AdminCredentials $domaincredentials -TenantName $TenantName -PoolName $HostPoolName -RegistrationToken $Registered.Token -StartAgent $true
            $addRdsh = Set-RdsSessionHost -TenantName $TenantName -HostPoolName $HostPoolName -Name $SessionHostName -AllowNewSession $true
}
}
else
{
Write-Output $allhosts.name
}