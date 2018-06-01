
$ResourceGroupName="RdmiTempTest"

$DelegateAdminpassword="Indian@123"
#$DelegateAdminUsername="admin@ptgmsft.onmicrosoft.com"
$DelegateAdminUsername="deepak.jena@peopletechcsp.onmicrosoft.com"
#$RDBrokerURL="https://rdbroker-jrsjosflw7jms.azurewebsites.net"
$RDBrokerURL="https://rdbroker-l6zmnj5fp42tm.azurewebsites.net/"

cd 'C:\PowershellModules'
Import-Module .\Microsoft.RDInfra.RDPowershell.dll
$Securepass=ConvertTo-SecureString -String $DelegateAdminpassword -AsPlainText -Force
$Credentials=New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList($DelegateAdminUsername, $Securepass)
#Setting RDS Context

Set-RdsContext -DeploymentUrl $RDBrokerURL -Credential $Credentials

$sessions=@()
$tenantname="PTG-Tenant"
#$hostpool="PTG-Hostpool"
#$hostpool="MSFT-Hostpool2"
$hostpool="MSFT-Hostpool"

$allshs=Get-RdsSessionHost -TenantName $tenantname -HostPoolName $hostpool

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
    [parameter(mandatory)]
    [String]$ResourceGroup,
    
    # The VM name to remove, regex are supported
    [parameter(mandatory)]
    [String]$VMName
 )

    # Remove the VM's and then remove the datadisks, osdisk, NICs
    Get-AzureRmVM -ResourceGroupName $ResourceGroup | Where Name -Match $VMName  | foreach {
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
                Get-AzureRmNetworkInterface -ResourceGroupName $ResourceGroup -Name $NICName | Remove-AzureRmNetworkInterface -Force
            }

            # Support to remove managed disks
            if($a.StorageProfile.OsDisk.ManagedDisk ) {
                ($DataDisks + $OSDisk) | ForEach-Object {
                    #Write-Warning -Message "Removing Disk: $_"
                    Get-AzureRmDisk -ResourceGroupName $ResourceGroup -DiskName $_ | Remove-AzureRmDisk -Force
                }
            }
            # Support to remove unmanaged disks (from Storage Account Blob)
            else {
                # This assumes that OSDISK and DATADisks are on the same blob storage account
                # Modify the function if that is not the case.
                $saname = ($a.StorageProfile.OsDisk.Vhd.Uri -split '\.' | Select -First 1) -split '//' |  Select -Last 1
                $sa = Get-AzureRmStorageAccount -ResourceGroupName $ResourceGroup -Name $saname
        
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
                
                #Remove bootdiagnostic disk
                <#$bootdiagcsdisk=$a.BootDiagnostics.ConsoleScreenshotBlobUri
                Remove-AzureStorageBlob -Blob  $bootdiagcsdisk
                
                $bootdiagssdisk=$a.BootDiagnostics.SerialConsoleLogBlobUri
                Remove-AzureStorageBlob -Blob  $bootdiagssdisk
                #>

                  

            }
            Remove-AzureRmResource -ResourceId $_.AvailabilitySetReference.Id -Force
            # If you are on the network you can cleanup the Computer Account in AD            
	        Get-ADComputer -Identity $a.OSProfile.ComputerName | Remove-ADObject -Recursive -confirm:$false
        
        }#PSCmdlet(ShouldProcess)
    }

}


try{

$sessionusers=0
$sessionusers=@()
$UPname=0
$UPname=@()
$sid=Get-RdsUserSession -TenantName $tenantname -HostPoolName $hostpool
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
}else{
foreach($ci in $cim){
foreach($user in $ci.Loggedon){
#$user
if($user -in $sessionusers){
$computers+=$ci.computer
#Send-RdsUserSessionMessage -TenantName $tenantname -HostPoolName $hostpool -SessionHostName $ci.computer -SessionId $ci.Sessionid -MessageTitle $MessageTitle -MessageBody $MessageBody -NoConfirm $false -ErrorAction SilentlyContinue
}
}
}
}
}
# setting rdsh vm in drain mode
$allcomputers=$computers | select -Unique

foreach($sh in $allcomputers){
write-host "insideblock"
Set-RdsSessionHost -TenantName $tenantname -HostPoolName $hostpool -Name $sh -AllowNewSession $false
#start-Sleep -Seconds 900
Remove-RdsSessionHost -TenantName $tenantname -HostPoolName $hostpool -Name $sh -Force $true
$LoadModule=Get-Module -ListAvailable "Azure*"
if(!$LoadModule){
Install-PackageProvider NuGet -Force
Install-Module -Name azurerm -AllowClobber -Force
}
Import-Module AzureRM.profile
Import-Module AzureRM.Compute
#Login-AzureRmAccount -SubscriptionName "RDMI Partner"
$VMName=$sh.Split(".")[0]

Remove-AzureRMVMInstanceResource -ResourceGroup $ResourceGroupName -VMName $VMName


}

}
catch{


}


