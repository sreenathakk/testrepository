﻿param(
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
    [string]$FileURI
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
$Securepass=ConvertTo-SecureString -String $DelegateAdminpassword -AsPlainText -Force
$Credentials=New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList($DelegateAdminUsername, $Securepass)

    #Setting RDS Context
    Set-RdsContext -DeploymentUrl $RDBrokerURL -Credential $Credentials

$sessions=@()


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

        $avset=@($_.AvailabilitySetReference.Id)

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
                
                $diagvmname=0
                $diag=$_.Name.ToLower()
                $diagvmname=$diag -replace '[\-]', ''
                $diagContainerName = ('bootdiagnostics-{0}-{1}' -f $diagvmname, $_.VmId)
                Set-AzureRmCurrentStorageAccount -Context $sa.Context
                Remove-AzureStorageContainer -Name $diagContainerName -Force
                

            }
            $DomainName=(Get-WmiObject win32_computersystem).Domain
            #
            # If you are on the network you can cleanup the Computer Account in AD            
	        Get-ADComputer -Identity $a.OSProfile.ComputerName | Remove-ADObject -Recursive -confirm:$false
            Remove-DnsServerResourceRecord -ZoneName $DomainName -RRType "A" -Name $a.OSProfile.ComputerName -Force -Confirm:$false
            return $avset
        }#PSCmdlet(ShouldProcess)
    }

    
}




  try{

            $sessionusers=0
            $sessionusers=@()
            $UPname=0
            $UPname=@()
                
                $sid=Get-RdsUserSession -TenantName $tenantname -HostPoolName $HostPoolName
            
            if($sid -ne 'null'){
                   
            $UPname+=$sid.UserPrincipalname
                foreach($u in $UPname){
                            if($u -ne 'null'){
                                $sessionusers+=$u.split("\")[1] 
                               }
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
                    $computer=$computers.Split(".")[0]
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

            $TenantLogin=Login-AzureRmAccount -Credential $Credentials -SubscriptionId $SubscriptionId

            foreach($sh in $allcomputers){
                
                # setting rdsh vm in drain mode
                Set-RdsSessionHost -TenantName $tenantname -HostPoolName $HostPoolName -Name $sh -AllowNewSession $false
                
                #Start-Sleep -Seconds 900
                
                Remove-RdsSessionHost -TenantName $tenantname -HostPoolName $HostPoolName -Name $sh -Force $true
                
                $LoadModule=Get-Module -ListAvailable "Azure*"
                
                if(!$LoadModule){
                    Install-PackageProvider NuGet -Force
                    Install-Module -Name azurerm -AllowClobber -Force
                    }
                        Import-Module AzureRM.profile
                        Import-Module AzureRM.Compute
                
                $VMName=$sh.Split(".")[0]
                
                $removeVM=Remove-AzureRMVMInstanceResource -VMName $VMName
                #$removeVM
                #Remove-AzureRmResource -ResourceId $removeVM -Force
                }


    }
        catch{


            }